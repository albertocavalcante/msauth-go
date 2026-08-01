package cache

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"

	"github.com/zalando/go-keyring"
)

// TestKeychainStore_ChunksLargeBlob verifies the chunking round-trips a blob
// far larger than go-keyring's macOS ~4 KB per-item command limit, and that the
// pieces are actually split across multiple keyring items. Uses the in-memory
// mock so it runs on any OS in CI.
func TestKeychainStore_ChunksLargeBlob(t *testing.T) {
	keyring.MockInit()
	ctx := context.Background()
	st := NewKeychainStoreWithService("msauth-test")

	blob := make([]byte, 5*keychainChunkSize+123) // ~10 KB, 6 chunks
	if _, err := rand.Read(blob); err != nil {
		t.Fatalf("rand: %v", err)
	}

	if err := st.Save(ctx, "acct", blob); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := st.Load(ctx, "acct")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !bytes.Equal(got, blob) {
		t.Fatalf("round-trip mismatch: got %d bytes, want %d", len(got), len(blob))
	}

	// The count marker plus 6 chunk items must exist individually.
	if c, err := keyring.Get("msauth-test", "acct"); err != nil || c != "6" {
		t.Errorf("count marker = %q, %v; want \"6\"", c, err)
	}
	if _, err := keyring.Get("msauth-test", chunkName("acct", 5)); err != nil {
		t.Errorf("chunk 5 missing: %v", err)
	}
}

func TestKeychainStore_ShrinkThenGrowAndDelete(t *testing.T) {
	keyring.MockInit()
	ctx := context.Background()
	st := NewKeychainStoreWithService("msauth-test")

	big := bytes.Repeat([]byte("A"), 4*keychainChunkSize)
	small := []byte("tiny")

	if err := st.Save(ctx, "k", big); err != nil {
		t.Fatalf("Save big: %v", err)
	}
	if err := st.Save(ctx, "k", small); err != nil {
		t.Fatalf("Save small: %v", err)
	}
	// Stale higher chunks from the big blob must be swept.
	if _, err := keyring.Get("msauth-test", chunkName("k", 1)); err == nil {
		t.Error("stale chunk 1 not cleaned up after shrink")
	}
	got, err := st.Load(ctx, "k")
	if err != nil || !bytes.Equal(got, small) {
		t.Fatalf("Load after shrink = %q, %v", got, err)
	}

	if err := st.Delete(ctx, "k"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got, _ := st.Load(ctx, "k"); got != nil {
		t.Errorf("after delete Load = %q, want nil", got)
	}
}

func TestKeychainStore_AbsentIsNilNil(t *testing.T) {
	keyring.MockInit()
	got, err := NewKeychainStoreWithService("msauth-test").Load(context.Background(), "missing")
	if err != nil || got != nil {
		t.Fatalf("absent Load = %q, %v; want nil, nil", got, err)
	}
}
