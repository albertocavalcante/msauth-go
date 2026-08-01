// Package msauthtest provides test doubles for msauth, so downstream packages
// can exercise auth-dependent code without real sign-in or a keyring.
package msauthtest

import (
	"context"
	"sync"

	"github.com/albertocavalcante/msauth-go/cache"
)

// MemStore is an in-memory [cache.Store] for tests. The zero value is not
// usable; construct it with [NewMemStore].
type MemStore struct {
	mu sync.Mutex
	m  map[string][]byte
}

// NewMemStore returns an empty in-memory Store.
func NewMemStore() *MemStore {
	return &MemStore{m: make(map[string][]byte)}
}

var _ cache.Store = (*MemStore)(nil)

// Load returns a copy of the stored blob, or (nil, nil) if absent.
func (s *MemStore) Load(_ context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.m[key]
	if !ok {
		return nil, nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out, nil
}

// Save stores a copy of blob under key.
func (s *MemStore) Save(_ context.Context, key string, blob []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := make([]byte, len(blob))
	copy(cp, blob)
	s.m[key] = cp
	return nil
}

// Delete removes key (absent key is not an error).
func (s *MemStore) Delete(_ context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, key)
	return nil
}

// Len reports how many keys are stored (test helper).
func (s *MemStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}
