package cache

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/zalando/go-keyring"
)

// DefaultKeychainService is the service name under which blobs are stored in
// the OS keyring (Keychain on macOS, Secret Service on Linux).
const DefaultKeychainService = "carteiro-msauth"

// keychainChunkSize is the max raw bytes stored per keyring item. go-keyring's
// macOS backend rejects any Set whose shell command exceeds 4096 bytes; after
// base64 (4/3) plus fixed overhead that caps a single item at ~2.9 KB of raw
// data. A real MSAL token-cache blob is commonly 3–6 KB (larger with multiple
// accounts), so we split it across items well under that ceiling and reassemble
// on Load. Without this, keychain.Set fails with ErrSetDataTooBig and the token
// cache silently never persists.
const keychainChunkSize = 2048

type keychainStore struct {
	service string
}

// NewKeychainStore returns a [Store] backed by the OS keyring under
// [DefaultKeychainService]. It shells out to the platform keyring via
// zalando/go-keyring and is cgo-free.
func NewKeychainStore() Store {
	return &keychainStore{service: DefaultKeychainService}
}

// NewKeychainStoreWithService is like [NewKeychainStore] with a custom service
// name (useful to isolate multiple apps or tests).
func NewKeychainStoreWithService(service string) Store {
	return &keychainStore{service: service}
}

func chunkName(key string, i int) string {
	return key + "#" + strconv.Itoa(i)
}

// Load reassembles the blob from its chunks. The count marker (stored under
// key) is written last on Save, so its presence implies a complete write.
func (k *keychainStore) Load(_ context.Context, key string) ([]byte, error) {
	countStr, err := keyring.Get(k.service, key)
	if errors.Is(err, keyring.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(countStr)
	if err != nil {
		return nil, fmt.Errorf("keychain: bad chunk count %q: %w", countStr, err)
	}
	var buf []byte
	for i := range n {
		c, err := keyring.Get(k.service, chunkName(key, i))
		if err != nil {
			return nil, fmt.Errorf("keychain: read chunk %d/%d: %w", i, n, err)
		}
		buf = append(buf, c...)
	}
	return buf, nil
}

// Save writes the blob as N chunks, then the count marker last as the commit
// point, then sweeps any stale trailing chunks left by a previously larger blob.
func (k *keychainStore) Save(_ context.Context, key string, blob []byte) error {
	n := (len(blob) + keychainChunkSize - 1) / keychainChunkSize
	if n == 0 {
		n = 1 // always at least one (possibly empty) chunk
	}
	for i := range n {
		start := i * keychainChunkSize
		end := min(start+keychainChunkSize, len(blob))
		if err := keyring.Set(k.service, chunkName(key, i), string(blob[start:end])); err != nil {
			return fmt.Errorf("keychain: write chunk %d: %w", i, err)
		}
	}
	if err := keyring.Set(k.service, key, strconv.Itoa(n)); err != nil {
		return fmt.Errorf("keychain: write count: %w", err)
	}
	// Best-effort cleanup of chunks beyond n (blob shrank since last save).
	for i := n; ; i++ {
		name := chunkName(key, i)
		if _, err := keyring.Get(k.service, name); errors.Is(err, keyring.ErrNotFound) {
			break
		}
		_ = keyring.Delete(k.service, name)
	}
	return nil
}

// Delete removes the count marker and all chunks (absent key is not an error).
func (k *keychainStore) Delete(_ context.Context, key string) error {
	if err := keyring.Delete(k.service, key); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return err
	}
	for i := 0; ; i++ {
		name := chunkName(key, i)
		if _, err := keyring.Get(k.service, name); errors.Is(err, keyring.ErrNotFound) {
			break
		}
		_ = keyring.Delete(k.service, name)
	}
	return nil
}
