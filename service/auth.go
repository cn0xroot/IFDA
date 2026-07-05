package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// pbkdf2 is RFC 2898 PBKDF2-HMAC-SHA256, reimplemented against stdlib only
// (crypto/hmac + crypto/sha256) rather than importing golang.org/x/crypto:
// the latest x/crypto requires Go >= 1.25, which would silently invalidate
// this project's documented "Go 1.22+" requirement (ENVIRONMENT.md) and pull
// in several transitive dependencies for one password hash. This is ~20
// lines of the same well-known algorithm with zero new dependencies.
func pbkdf2(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen
	dk := make([]byte, 0, numBlocks*hashLen)
	var buf [4]byte
	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		buf[0], buf[1], buf[2], buf[3] = byte(block>>24), byte(block>>16), byte(block>>8), byte(block)
		prf.Write(buf[:])
		u := prf.Sum(nil)
		result := append([]byte(nil), u...)
		for n := 1; n < iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(nil)
			for x := range result {
				result[x] ^= u[x]
			}
		}
		dk = append(dk, result...)
	}
	return dk[:keyLen]
}

const pbkdf2Iterations = 100000 // ~50-150ms per login on modern hardware

type userRecord struct {
	Salt string `json:"salt"` // hex
	Hash string `json:"hash"` // hex, pbkdf2(password, salt)
}

type sessionInfo struct {
	username string
	expires  time.Time
}

const sessionTTL = 24 * time.Hour

// loginAttempts tracks failed logins per username for lockout (brute-force
// defense). Deliberately per-username rather than per-IP: this is a small
// internal tool behind whatever reverse proxy/NAT a deployer uses, so a
// client IP isn't reliably meaningful, but "5 wrong passwords for admin" is.
type loginAttempts struct {
	count       int
	lockedUntil time.Time
}

const maxFailedAttempts = 5
const lockoutDuration = 5 * time.Minute

// AuthStore holds login credentials (file-backed, hashed+salted — never
// plaintext) and active sessions (in-memory only: a service restart requires
// logging in again, which is a simpler and safer tradeoff than persisting
// live session secrets to disk).
type AuthStore struct {
	mu       sync.RWMutex
	path     string
	users    map[string]userRecord
	sessions map[string]sessionInfo
	attempts map[string]*loginAttempts
}

func NewAuthStore(path string) *AuthStore {
	s := &AuthStore{path: path, users: map[string]userRecord{}, sessions: map[string]sessionInfo{},
		attempts: map[string]*loginAttempts{}}
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &s.users)
	}
	return s
}

func (s *AuthStore) HasUsers() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users) > 0
}

func (s *AuthStore) HasUser(username string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.users[username]
	return ok
}

func (s *AuthStore) hash(password, saltHex string) string {
	salt, _ := hex.DecodeString(saltHex)
	return hex.EncodeToString(pbkdf2([]byte(password), salt, pbkdf2Iterations, 32))
}

// SetPassword creates or updates a user's credentials.
func (s *AuthStore) SetPassword(username, password string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	saltBytes := make([]byte, 16)
	rand.Read(saltBytes)
	salt := hex.EncodeToString(saltBytes)
	s.users[username] = userRecord{Salt: salt, Hash: s.hash(password, salt)}
	s.persist()
}

func (s *AuthStore) persist() { // caller holds the write lock
	if s.path == "" {
		return
	}
	data, err := json.MarshalIndent(s.users, "", "  ")
	if err != nil {
		return
	}
	tmp := s.path + ".tmp"
	if os.WriteFile(tmp, data, 0o600) == nil {
		_ = os.Rename(tmp, s.path)
	}
}

// verify checks a password against the stored hash without touching sessions
// or the failed-attempt counter, so it can be reused by both Login and
// change-password (which must re-check the *current* password) without
// side effects like minting an unwanted extra session.
func (s *AuthStore) verify(username, password string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.users[username]
	if !ok {
		return false
	}
	want := s.hash(password, rec.Salt)
	return subtle.ConstantTimeCompare([]byte(want), []byte(rec.Hash)) == 1
}

// Login checks credentials and, on success, issues a new session token.
// Caller is expected to check Locked() first and call RecordFailure/
// RecordSuccess to maintain the lockout counter (kept separate from Login
// itself so the API layer can return a distinct "locked out" response
// before ever touching the password hash).
func (s *AuthStore) Login(username, password string) (string, bool) {
	if !s.verify(username, password) {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	tokBytes := make([]byte, 32)
	rand.Read(tokBytes)
	tok := hex.EncodeToString(tokBytes)
	s.sessions[tok] = sessionInfo{username: username, expires: time.Now().Add(sessionTTL)}
	return tok, true
}

// Locked reports whether username is currently locked out, and for how long.
func (s *AuthStore) Locked(username string) (time.Duration, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.attempts[username]
	if !ok || a.lockedUntil.IsZero() || !time.Now().Before(a.lockedUntil) {
		return 0, false
	}
	return time.Until(a.lockedUntil), true
}

// RecordFailure counts a wrong-password attempt, locking the account out
// once maxFailedAttempts is reached within the lockout window.
func (s *AuthStore) RecordFailure(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.attempts[username]
	if a == nil {
		a = &loginAttempts{}
		s.attempts[username] = a
	}
	a.count++
	if a.count >= maxFailedAttempts {
		a.lockedUntil = time.Now().Add(lockoutDuration)
		a.count = 0
	}
}

// RecordSuccess clears the failed-attempt counter after a good login.
func (s *AuthStore) RecordSuccess(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.attempts, username)
}

// Check validates a session token, returning the logged-in username.
func (s *AuthStore) Check(token string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	info, ok := s.sessions[token]
	if !ok || time.Now().After(info.expires) {
		return "", false
	}
	return info.username, true
}

func (s *AuthStore) Logout(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, token)
}
