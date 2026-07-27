package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// aiKeySize is 32 bytes for AES-256.
const aiKeySize = 32

// loadOrCreateAIKey loads the local symmetric key used to encrypt AI provider
// API keys at rest, generating one on first run. Unlike auth.go's PBKDF2
// login-password hash (one-way, verify-only), an AI provider's API key must
// be retrievable in plaintext later to send to that provider -- so it can't
// reuse that scheme. This key file is the resulting new trust boundary: back
// it up alongside reports.db/users.json, since losing it permanently strands
// (not exposes) every stored AI provider key -- see main.go's startup log.
func loadOrCreateAIKey(dataDir string) ([]byte, error) {
	path := filepath.Join(dataDir, "ai.key")
	if data, err := os.ReadFile(path); err == nil {
		if len(data) != aiKeySize {
			return nil, errors.New("ai.key has unexpected length; delete it to generate a fresh one (invalidates stored AI provider keys)")
		}
		return data, nil
	}
	key := make([]byte, aiKeySize)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	// Crash-safe write, mirroring AuthStore.persist(): a partial write from a
	// killed process must never leave a corrupt/truncated key file behind.
	if err := writeKeyFile(path, key); err != nil {
		return nil, err
	}
	return key, nil
}

// encryptSecret AES-256-GCM-encrypts plaintext under key, returning
// base64(nonce || ciphertext) for storage in a TEXT column.
func encryptSecret(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// decryptSecret reverses encryptSecret.
func decryptSecret(key []byte, encoded string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}
	nonce, ct := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// keyLast4 captures a display hint for a plaintext secret before it's
// encrypted -- the ciphertext cannot be partially decoded later, so this
// must be computed at write time while the plaintext is still in hand.
func keyLast4(plaintext string) string {
	if len(plaintext) <= 4 {
		return plaintext
	}
	return plaintext[len(plaintext)-4:]
}

// writeKeyFile writes key to path with the crash-safe temp+rename pattern
// used elsewhere for sensitive state (see AuthStore.persist).
func writeKeyFile(path string, key []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, key, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// rotateAIKey re-encrypts every stored provider API key under a freshly
// generated ai.key, then swaps the key file in. Intended to be run at
// startup (via -rotate-ai-key) while nothing is serving, so no request can
// be mid-decrypt during the swap.
//
// Ordering is chosen so the failure modes are recoverable rather than
// destructive:
//
//   - Every key is decrypted up front, before anything is written. A wrong
//     or corrupt existing ai.key therefore aborts with nothing changed,
//     rather than half-rotating.
//   - The database swap is one transaction: providers are never left split
//     across two keys.
//   - The outgoing key is copied to ai.key.bak-<timestamp> *before* the
//     new one is installed, so the small window between the database
//     commit and the key-file rename is manually recoverable (restore the
//     backup, or re-run rotation) instead of stranding every stored key.
//
// A no-provider database still rotates the key file; there is simply
// nothing to re-encrypt.
func rotateAIKey(dataDir string, reportDB *ReportDB) error {
	path := filepath.Join(dataDir, "ai.key")
	oldKey, err := loadOrCreateAIKey(dataDir)
	if err != nil {
		return fmt.Errorf("rotate ai.key: load current key: %w", err)
	}

	providers, err := reportDB.ListProviders()
	if err != nil {
		return fmt.Errorf("rotate ai.key: list providers: %w", err)
	}

	// Decrypt everything first: fail before touching any state if the
	// current key can't actually read what's stored.
	plaintexts := make(map[string]string, len(providers))
	for _, p := range providers {
		plain, err := decryptSecret(oldKey, p.APIKeyEnc)
		if err != nil {
			return fmt.Errorf("rotate ai.key: provider %q (%s) could not be decrypted with the current key, "+
				"so rotation would strand it; nothing has been changed: %w", p.Name, p.ID, err)
		}
		plaintexts[p.ID] = plain
	}

	newKey := make([]byte, aiKeySize)
	if _, err := rand.Read(newKey); err != nil {
		return fmt.Errorf("rotate ai.key: generate new key: %w", err)
	}
	reencrypted := make(map[string]string, len(plaintexts))
	for id, plain := range plaintexts {
		enc, err := encryptSecret(newKey, plain)
		if err != nil {
			return fmt.Errorf("rotate ai.key: re-encrypt provider %s: %w", id, err)
		}
		reencrypted[id] = enc
	}

	backup := fmt.Sprintf("%s.bak-%s", path, time.Now().UTC().Format("20060102T150405Z"))
	if err := writeKeyFile(backup, oldKey); err != nil {
		return fmt.Errorf("rotate ai.key: could not back up the current key, refusing to proceed: %w", err)
	}

	if err := reportDB.ReplaceProviderKeyCiphertexts(reencrypted); err != nil {
		return fmt.Errorf("rotate ai.key: re-encrypting providers failed, key file left unchanged: %w", err)
	}
	if err := writeKeyFile(path, newKey); err != nil {
		return fmt.Errorf("rotate ai.key: providers were re-encrypted but installing the new key failed -- "+
			"restore %s over %s, or re-add providers: %w", backup, path, err)
	}

	// Read back through the full path to prove the rotation actually took.
	verifyKey, err := loadOrCreateAIKey(dataDir)
	if err != nil {
		return fmt.Errorf("rotate ai.key: could not re-read the new key: %w", err)
	}
	after, err := reportDB.ListProviders()
	if err != nil {
		return fmt.Errorf("rotate ai.key: could not re-read providers for verification: %w", err)
	}
	for _, p := range after {
		plain, err := decryptSecret(verifyKey, p.APIKeyEnc)
		if err != nil || plain != plaintexts[p.ID] {
			return fmt.Errorf("rotate ai.key: verification failed for provider %q (%s) -- "+
				"restore %s over %s: %w", p.Name, p.ID, backup, path, err)
		}
	}

	log.Printf("rotated ai.key: re-encrypted %d provider key(s); previous key backed up at %s "+
		"(delete it once you're satisfied the rotation is good)", len(after), backup)
	return nil
}
