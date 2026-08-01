package cache

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// fileStore is an AES-256-GCM encrypted-file [Store] for headless or non-macOS
// use. The encryption key is a 32-byte random file (cache.key, 0600) created on
// first use inside dir; each cache blob is written as <hash>.enc (0600) with a
// random nonce prepended to the ciphertext.
//
// This protects the refresh token at rest against casual disk reads, but the
// key sits beside the data — it is weaker than the OS Keychain and is intended
// as a fallback where no keyring is available. Prefer [NewKeychainStore].
type fileStore struct {
	dir string
}

// NewFileStore returns an encrypted-file [Store] rooted at dir. The directory
// is created (0700) on first write.
func NewFileStore(dir string) Store {
	return &fileStore{dir: dir}
}

const keyFileName = "cache.key"

func (f *fileStore) keyBytes() ([]byte, error) {
	p := filepath.Join(f.dir, keyFileName)
	if b, err := readKey(p); err == nil {
		return b, nil // fast path: key already exists
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.MkdirAll(f.dir, 0o700); err != nil {
		return nil, err
	}
	nk := make([]byte, 32)
	if _, err := rand.Read(nk); err != nil {
		return nil, err
	}
	// Create atomically: O_EXCL means concurrent first-writers can't clobber
	// each other's key (which would make blobs encrypted under the loser
	// permanently undecryptable). On a lost race, adopt the winner's key.
	fh, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, os.ErrExist) {
		return readKey(p)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = fh.Close() }()
	if _, err := fh.Write(nk); err != nil {
		return nil, err
	}
	if err := fh.Sync(); err != nil {
		return nil, err
	}
	return nk, nil
}

func readKey(p string) ([]byte, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("cache key %s is corrupt (want 32 bytes, got %d)", p, len(b))
	}
	return b, nil
}

func (f *fileStore) gcm() (cipher.AEAD, error) {
	kb, err := f.keyBytes()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(kb)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (f *fileStore) path(key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(f.dir, hex.EncodeToString(sum[:16])+".enc")
}

func (f *fileStore) Load(_ context.Context, key string) ([]byte, error) {
	ct, err := os.ReadFile(f.path(key))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	gcm, err := f.gcm()
	if err != nil {
		return nil, err
	}
	if len(ct) < gcm.NonceSize() {
		return nil, errors.New("cache: ciphertext too short")
	}
	nonce, enc := ct[:gcm.NonceSize()], ct[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, enc, nil)
	if err != nil {
		return nil, fmt.Errorf("cache: decrypt: %w", err)
	}
	return plain, nil
}

func (f *fileStore) Save(_ context.Context, key string, blob []byte) error {
	gcm, err := f.gcm()
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ct := gcm.Seal(nonce, nonce, blob, nil)
	if err := os.MkdirAll(f.dir, 0o700); err != nil {
		return err
	}
	// Atomic write via a UNIQUE temp file then rename. A unique name (not a
	// fixed dst+".tmp") means concurrent writers — two goroutines or two
	// processes sharing the dir — never splice each other's bytes into one
	// temp file; the rename is atomic, so dst is always a complete blob from
	// some single writer (last-writer-wins), never a corrupt splice. Sync
	// before rename gives the crash-durability the temp+rename implies.
	dst := f.path(key)
	tmp, err := os.CreateTemp(f.dir, ".cache-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	if err := writeSyncClose(tmp, ct); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, dst); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return nil
}

func writeSyncClose(f *os.File, data []byte) error {
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func (f *fileStore) Delete(_ context.Context, key string) error {
	err := os.Remove(f.path(key))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
