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
// is made private on first use: mode 0700 on Unix, or a current-user-only
// protected DACL on Windows. New cache files are private to that user too.
// Operations reject an empty dir; use "." explicitly to select the working directory.
func NewFileStore(dir string) Store {
	return &fileStore{dir: dir}
}

const keyFileName = "cache.key"

func (f *fileStore) validateDir() error {
	if f.dir == "" {
		return errors.New("cache: empty file-store directory")
	}
	return nil
}

func (f *fileStore) keyBytes() ([]byte, error) {
	p := filepath.Join(f.dir, keyFileName)
	// Reject invalid existing key paths before changing directory permissions.
	// On Windows, a parent DACL update may normalize inherited child ACE flags.
	if err := validateKeyFile(p); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err := ensurePrivateDir(f.dir); err != nil {
		return nil, err
	}
	if b, err := readKey(p); err == nil {
		return b, nil // fast path: key already exists
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	nk := make([]byte, 32)
	if _, err := rand.Read(nk); err != nil {
		return nil, err
	}
	// Publish only a fully written key. O_EXCL on the final path would expose
	// an empty/partial key to another first writer before Write completes.
	fh, err := os.CreateTemp(f.dir, ".cache-key-*.tmp")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.Remove(fh.Name()) }()
	if err := setPrivateFilePermissions(fh.Name()); err != nil {
		_ = fh.Close()
		return nil, err
	}
	if err := writeSyncClose(fh, nk); err != nil {
		return nil, err
	}
	if err := os.Link(fh.Name(), p); errors.Is(err, os.ErrExist) {
		return readKey(p)
	} else if err != nil {
		return nil, err
	}
	return nk, nil
}

func validateKeyFile(p string) error {
	info, err := os.Lstat(p)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("cache: encryption key must be a regular file")
	}
	return nil
}

func readKey(p string) ([]byte, error) {
	if err := validateKeyFile(p); err != nil {
		return nil, err
	}
	if err := setPrivateFilePermissions(p); err != nil {
		return nil, err
	}
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
	if err := f.validateDir(); err != nil {
		return nil, err
	}
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
	if err := f.validateDir(); err != nil {
		return err
	}
	gcm, err := f.gcm()
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	ct := gcm.Seal(nonce, nonce, blob, nil)
	if err := ensurePrivateDir(f.dir); err != nil {
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
	if err := setPrivateFilePermissions(tmpName); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
		return err
	}
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

func ensurePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return setPrivateDirPermissions(dir)
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
	if err := f.validateDir(); err != nil {
		return err
	}
	err := os.Remove(f.path(key))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
