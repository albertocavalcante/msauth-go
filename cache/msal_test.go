package cache

import (
	"bytes"
	"context"
	"sync"
	"testing"

	msalcache "github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"
)

// memStore is a tiny local in-memory Store (avoids importing msauthtest here).
type memStore struct {
	mu sync.Mutex
	m  map[string][]byte
}

func newMem() *memStore { return &memStore{m: map[string][]byte{}} }

func (s *memStore) Load(_ context.Context, k string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.m[k], nil
}
func (s *memStore) Save(_ context.Context, k string, b []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[k] = b
	return nil
}
func (s *memStore) Delete(_ context.Context, k string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, k)
	return nil
}

// blobCache implements MSAL's Marshaler/Unmarshaler with a fixed payload.
type blobCache struct{ data []byte }

func (b *blobCache) Marshal() ([]byte, error) { return b.data, nil }
func (b *blobCache) Unmarshal(p []byte) error { b.data = append([]byte(nil), p...); return nil }

func TestMSALAccessor_ExportThenReplace(t *testing.T) {
	store := newMem()
	acc := NewMSALAccessor(store, "msauth:client")
	ctx := context.Background()

	payload := []byte(`{"cache":"blob"}`)
	if err := acc.Export(ctx, &blobCache{data: payload}, msalcache.ExportHints{}); err != nil {
		t.Fatalf("Export: %v", err)
	}

	dst := &blobCache{}
	if err := acc.Replace(ctx, dst, msalcache.ReplaceHints{}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if !bytes.Equal(dst.data, payload) {
		t.Errorf("round-trip = %q, want %q", dst.data, payload)
	}
}

func TestMSALAccessor_ReplaceAbsentIsNoop(t *testing.T) {
	acc := NewMSALAccessor(newMem(), "missing")
	dst := &blobCache{data: []byte("untouched")}
	if err := acc.Replace(context.Background(), dst, msalcache.ReplaceHints{}); err != nil {
		t.Fatalf("Replace absent: %v", err)
	}
	if string(dst.data) != "untouched" {
		t.Errorf("absent Replace mutated cache: %q", dst.data)
	}
}
