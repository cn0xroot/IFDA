package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key := make([]byte, aiKeySize)
	for i := range key {
		key[i] = byte(i)
	}
	enc, err := encryptSecret(key, "sk-super-secret-value")
	if err != nil {
		t.Fatal(err)
	}
	if enc == "sk-super-secret-value" {
		t.Fatal("encryptSecret must not return the plaintext unchanged")
	}
	plain, err := decryptSecret(key, enc)
	if err != nil {
		t.Fatal(err)
	}
	if plain != "sk-super-secret-value" {
		t.Errorf("decryptSecret = %q, want sk-super-secret-value", plain)
	}
}

// A key file loss (or a bug that decrypts with the wrong key) must fail
// loudly, not silently return garbage that looks like a valid API key.
func TestDecryptFailsWithWrongKey(t *testing.T) {
	key1 := make([]byte, aiKeySize)
	key2 := make([]byte, aiKeySize)
	key2[0] = 1 // differ from key1 (all zero)
	enc, err := encryptSecret(key1, "sk-secret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decryptSecret(key2, enc); err == nil {
		t.Error("decrypting with the wrong key must fail, not return garbage")
	}
}

func TestLoadOrCreateAIKeyPersistsAcrossCalls(t *testing.T) {
	dir := t.TempDir()
	key1, err := loadOrCreateAIKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(key1) != aiKeySize {
		t.Fatalf("key length = %d, want %d", len(key1), aiKeySize)
	}
	key2, err := loadOrCreateAIKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(key1) != string(key2) {
		t.Error("a second call on the same data dir must return the same key, not generate a fresh one")
	}
}

// Rotation must leave every provider readable under the new key, change
// the key on disk, and keep a backup of the outgoing one.
func TestRotateAIKeyReEncryptsProviders(t *testing.T) {
	dir := t.TempDir()
	db, err := NewReportDB(filepath.Join(dir, "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	oldKey, err := loadOrCreateAIKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	secrets := map[string]string{"ai-1": "sk-first-secret", "ai-2": "sk-second-secret"}
	for id, plain := range secrets {
		enc, err := encryptSecret(oldKey, plain)
		if err != nil {
			t.Fatal(err)
		}
		if err := db.CreateProvider(AIProvider{ID: id, Name: id, Host: "https://h", APIKeyEnc: enc,
			KeyLast4: keyLast4(plain), Model: "m", Kind: "openai", MaxTokens: 4096,
			CreatedAt: "now", UpdatedAt: "now"}); err != nil {
			t.Fatal(err)
		}
	}
	beforeCiphertexts := map[string]string{}
	for _, p := range mustList(t, db) {
		beforeCiphertexts[p.ID] = p.APIKeyEnc
	}

	if err := rotateAIKey(dir, db); err != nil {
		t.Fatal(err)
	}

	newKey, err := loadOrCreateAIKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(newKey) == string(oldKey) {
		t.Fatal("the key on disk must actually change")
	}
	for _, p := range mustList(t, db) {
		if p.APIKeyEnc == beforeCiphertexts[p.ID] {
			t.Errorf("provider %s ciphertext unchanged; it was not re-encrypted", p.ID)
		}
		plain, err := decryptSecret(newKey, p.APIKeyEnc)
		if err != nil {
			t.Fatalf("provider %s not decryptable with the new key: %v", p.ID, err)
		}
		if plain != secrets[p.ID] {
			t.Errorf("provider %s decrypted to %q, want %q", p.ID, plain, secrets[p.ID])
		}
		if _, err := decryptSecret(oldKey, p.APIKeyEnc); err == nil {
			t.Errorf("provider %s still decrypts under the OLD key; rotation was not real", p.ID)
		}
	}

	// The outgoing key must be recoverable.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var backup string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "ai.key.bak-") {
			backup = filepath.Join(dir, e.Name())
		}
	}
	if backup == "" {
		t.Fatal("rotation must leave a backup of the previous key")
	}
	data, err := os.ReadFile(backup)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(oldKey) {
		t.Error("backup does not contain the previous key")
	}
	if info, _ := os.Stat(backup); info != nil && info.Mode().Perm() != 0o600 {
		t.Errorf("backup key permissions = %o, want 0600", info.Mode().Perm())
	}
}

// If any stored key can't be read with the current ai.key, rotation must
// abort having changed nothing -- proceeding would strand that provider
// permanently under a key nobody has.
func TestRotateAIKeyAbortsWithoutChangesIfAnyProviderUndecryptable(t *testing.T) {
	dir := t.TempDir()
	db, err := NewReportDB(filepath.Join(dir, "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := loadOrCreateAIKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	good, _ := encryptSecret(key, "sk-good")
	if err := db.CreateProvider(AIProvider{ID: "ai-good", Name: "good", Host: "h", APIKeyEnc: good,
		KeyLast4: "good", Model: "m", Kind: "openai", MaxTokens: 4096, CreatedAt: "n", UpdatedAt: "n"}); err != nil {
		t.Fatal(err)
	}
	// Encrypted under a foreign key -- e.g. a row carried over from a
	// restore where ai.key didn't come along.
	foreign := make([]byte, aiKeySize)
	foreign[0] = 0xAB
	bad, _ := encryptSecret(foreign, "sk-bad")
	if err := db.CreateProvider(AIProvider{ID: "ai-bad", Name: "bad", Host: "h", APIKeyEnc: bad,
		KeyLast4: "bad", Model: "m", Kind: "openai", MaxTokens: 4096, CreatedAt: "n", UpdatedAt: "n"}); err != nil {
		t.Fatal(err)
	}

	err = rotateAIKey(dir, db)
	if err == nil {
		t.Fatal("rotation must fail when a provider can't be decrypted with the current key")
	}
	if !strings.Contains(err.Error(), "nothing has been changed") {
		t.Errorf("error should make clear no state was mutated, got: %v", err)
	}

	keyAfter, err := loadOrCreateAIKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(keyAfter) != string(key) {
		t.Error("ai.key must be untouched after an aborted rotation")
	}
	for _, p := range mustList(t, db) {
		switch p.ID {
		case "ai-good":
			if p.APIKeyEnc != good {
				t.Error("a readable provider's ciphertext must be untouched after an aborted rotation")
			}
		case "ai-bad":
			if p.APIKeyEnc != bad {
				t.Error("the unreadable provider's ciphertext must be untouched after an aborted rotation")
			}
		}
	}
}

// Rotating with no providers configured is a valid no-op-plus-new-key.
func TestRotateAIKeyWithNoProviders(t *testing.T) {
	dir := t.TempDir()
	db, err := NewReportDB(filepath.Join(dir, "reports.db"))
	if err != nil {
		t.Fatal(err)
	}
	oldKey, err := loadOrCreateAIKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := rotateAIKey(dir, db); err != nil {
		t.Fatal(err)
	}
	newKey, err := loadOrCreateAIKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(newKey) == string(oldKey) {
		t.Error("the key must still be replaced even with nothing to re-encrypt")
	}
}

func mustList(t *testing.T, db *ReportDB) []AIProvider {
	t.Helper()
	ps, err := db.ListProviders()
	if err != nil {
		t.Fatal(err)
	}
	return ps
}

func TestAIKeyFilePermissions(t *testing.T) {
	dir := t.TempDir()
	if _, err := loadOrCreateAIKey(dir); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "ai.key"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("ai.key permissions = %o, want 0600", perm)
	}
}
