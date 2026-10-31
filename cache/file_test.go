package cache

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestFileStore_RoundTripAndPersistence(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	blob := []byte(`{"token":"secret-refresh"}`)

	st := NewFileStore(dir)
	if err := st.Save(ctx, "acct", blob); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := st.Load(ctx, "acct")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(got, blob) {
		t.Fatalf("Load = %q, want %q", got, blob)
	}

	// A fresh instance over the same dir must read the same data (same key file).
	if got, err := NewFileStore(dir).Load(ctx, "acct"); err != nil || !bytes.Equal(got, blob) {
		t.Fatalf("persistence: got %q err %v", got, err)
	}

	// Ciphertext on disk must not contain the plaintext secret.
	files, _ := filepath.Glob(filepath.Join(dir, "*.enc"))
	if len(files) != 1 {
		t.Fatalf("want 1 .enc file, got %d", len(files))
	}
	raw, _ := os.ReadFile(files[0])
	if bytes.Contains(raw, []byte("secret-refresh")) {
		t.Error("plaintext secret found in ciphertext file")
	}

	// The unique temp file must have been renamed away, not left behind.
	if tmps, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(tmps) != 0 {
		t.Errorf("leftover temp files: %v", tmps)
	}
}

func TestFileStore_TightensExistingDirectoryPermissions(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}

	st := NewFileStore(dir)
	if err := st.Save(context.Background(), "acct", []byte("secret")); err != nil {
		t.Fatalf("Save: %v", err)
	}

	files, _ := filepath.Glob(filepath.Join(dir, "*.enc"))
	if len(files) != 1 {
		t.Fatalf("want 1 .enc file, got %d", len(files))
	}
	assertPrivateCachePermissions(t, dir, filepath.Join(dir, keyFileName), files[0])
}

func TestFileStoreRejectsNonregularKeyWithoutChangingIt(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, keyFileName)
	if err := os.Mkdir(key, 0o755); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := NewFileStore(dir).Save(t.Context(), "cache", []byte("synthetic")); err == nil {
		t.Fatal("accepted a directory as an encryption key")
	}
	after, err := os.Stat(key)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode() != before.Mode() {
		t.Fatalf("invalid key was modified: %v -> %v", before.Mode(), after.Mode())
	}
}

func TestFileTransactionRejectsInvalidKeyBeforeChangingPermissions(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(dir, keyFileName)
	if err := os.Mkdir(key, 0o755); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(key, "unrelated")
	if err := os.WriteFile(child, []byte("synthetic"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := map[string]os.FileMode{}
	for _, path := range []string{dir, key, child} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		before[path] = info.Mode()
	}
	err := Transact(t.Context(), NewFileStore(dir), func(Store) error {
		t.Fatal("invalid key reached transaction callback")
		return nil
	})
	if err == nil {
		t.Fatal("accepted a directory as an encryption key")
	}
	for path, want := range before {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode() != want {
			t.Fatalf("rejected transaction changed %s permissions: %v -> %v", path, want, info.Mode())
		}
	}
}

func TestFileStore_AbsentAndDelete(t *testing.T) {
	ctx := context.Background()
	st := NewFileStore(t.TempDir())

	if got, err := st.Load(ctx, "nope"); err != nil || got != nil {
		t.Fatalf("absent Load = %q, %v; want nil,nil", got, err)
	}
	if err := st.Delete(ctx, "nope"); err != nil {
		t.Fatalf("Delete absent: %v", err)
	}
	if err := st.Save(ctx, "k", []byte("v")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := st.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got, _ := st.Load(ctx, "k"); got != nil {
		t.Errorf("after delete Load = %q, want nil", got)
	}
}

func TestFileStore_TamperedCiphertextFails(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	st := NewFileStore(dir)
	if err := st.Save(ctx, "k", []byte("hello")); err != nil {
		t.Fatalf("Save: %v", err)
	}
	files, _ := filepath.Glob(filepath.Join(dir, "*.enc"))
	raw, _ := os.ReadFile(files[0])
	raw[len(raw)-1] ^= 0xFF // flip a ciphertext byte
	if err := os.WriteFile(files[0], raw, 0o600); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	if _, err := st.Load(ctx, "k"); err == nil {
		t.Error("expected decrypt error on tampered ciphertext")
	}
}

func TestFileStore_CorruptKeyFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, keyFileName), []byte("too-short"), 0o600); err != nil {
		t.Fatalf("seed key: %v", err)
	}
	if err := NewFileStore(dir).Save(context.Background(), "k", []byte("v")); err == nil {
		t.Error("expected error with corrupt key file")
	}
}
