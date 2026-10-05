package cache

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

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

// A v2 marker names immutable chunks. The legacy marker is only a count.
type chunkMarker struct {
	generation string
	count      int
	digest     string
}

func (m chunkMarker) encode() string {
	if m.generation == "" {
		return strconv.Itoa(m.count)
	}
	return "v2:" + m.generation + ":" + strconv.Itoa(m.count) + ":" + m.digest
}

func parseMarker(raw string) (chunkMarker, error) {
	if !strings.HasPrefix(raw, "v2:") {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			return chunkMarker{}, fmt.Errorf("keychain: invalid legacy chunk count %q", raw)
		}
		return chunkMarker{count: n}, nil
	}
	parts := strings.Split(raw[3:], ":")
	if len(parts) != 3 || len(parts[0]) != 32 || len(parts[2]) != 64 {
		return chunkMarker{}, errors.New("keychain: invalid versioned marker")
	}
	if _, err := hex.DecodeString(parts[0]); err != nil {
		return chunkMarker{}, fmt.Errorf("keychain: invalid generation: %w", err)
	}
	if _, err := hex.DecodeString(parts[2]); err != nil {
		return chunkMarker{}, fmt.Errorf("keychain: invalid digest: %w", err)
	}
	n, err := strconv.Atoi(parts[1])
	if err != nil || n < 1 {
		return chunkMarker{}, errors.New("keychain: invalid versioned chunk count")
	}
	return chunkMarker{generation: parts[0], count: n, digest: parts[2]}, nil
}

func (k *keychainStore) marker(key string) (chunkMarker, bool, error) {
	raw, err := keyring.Get(k.service, key)
	if errors.Is(err, keyring.ErrNotFound) {
		return chunkMarker{}, false, nil
	}
	if err != nil {
		return chunkMarker{}, false, err
	}
	m, err := parseMarker(raw)
	return m, true, err
}

func (k *keychainStore) name(key string, m chunkMarker, i int) string {
	if m.generation == "" {
		return chunkName(key, i)
	}
	return key + "#" + m.generation + "#" + strconv.Itoa(i)
}

func (k *keychainStore) read(key string, m chunkMarker) ([]byte, error) {
	var buf []byte
	for i := range m.count {
		c, err := keyring.Get(k.service, k.name(key, m, i))
		if err != nil {
			return nil, fmt.Errorf("keychain: read chunk %d/%d: %w", i, m.count, err)
		}
		buf = append(buf, c...)
	}
	if m.generation != "" {
		digest := sha256.Sum256(buf)
		if hex.EncodeToString(digest[:]) != m.digest {
			return nil, errors.New("keychain: chunk digest mismatch")
		}
	}
	return buf, nil
}

func (k *keychainStore) removeChunks(key string, m chunkMarker) {
	for i := range m.count {
		_ = keyring.Delete(k.service, k.name(key, m, i))
	}
}

// Load accepts legacy count markers and recovers the previous complete
// generation when the current generation is damaged.
func (k *keychainStore) Load(_ context.Context, key string) ([]byte, error) {
	unlock, err := lockKeychain(k.service, key)
	if err != nil {
		return nil, err
	}
	defer unlock()
	m, found, err := k.marker(key)
	if !found && err == nil {
		return nil, nil
	}
	if err == nil {
		if buf, readErr := k.read(key, m); readErr == nil {
			return buf, nil
		} else {
			err = readErr
		}
	}
	previous, found, prevErr := k.marker(key + "#previous")
	if prevErr == nil && found {
		if recovered, readErr := k.read(key, previous); readErr == nil {
			return recovered, nil
		}
	}
	return nil, err
}

// Save verifies a new immutable generation before publishing its marker.
// A process crash or concurrent cooperating process cannot tear the active
// generation. The last complete generation remains available for recovery.
func (k *keychainStore) Save(_ context.Context, key string, blob []byte) error {
	unlock, err := lockKeychain(k.service, key)
	if err != nil {
		return err
	}
	defer unlock()
	current, found, err := k.marker(key)
	// An invalid marker can still be repaired by a new Save. Preserve any
	// existing backup rather than copying the invalid marker over it.
	if err != nil {
		found = false
	}
	previous, hadPrevious, err := k.marker(key + "#previous")
	if err != nil {
		return err
	}
	usableCurrent := false
	if found {
		_, readErr := k.read(key, current)
		usableCurrent = readErr == nil
	}
	version := make([]byte, 16)
	if _, err := rand.Read(version); err != nil {
		return err
	}
	digest := sha256.Sum256(blob)
	n := max(1, (len(blob)+keychainChunkSize-1)/keychainChunkSize)
	next := chunkMarker{generation: hex.EncodeToString(version), count: n, digest: hex.EncodeToString(digest[:])}
	for i := range n {
		start := i * keychainChunkSize
		end := min(start+keychainChunkSize, len(blob))
		if err := keyring.Set(k.service, k.name(key, next, i), string(blob[start:end])); err != nil {
			return fmt.Errorf("keychain: write chunk %d: %w", i, err)
		}
	}
	if _, err := k.read(key, next); err != nil {
		return fmt.Errorf("keychain: verify new generation: %w", err)
	}
	if usableCurrent {
		if err := keyring.Set(k.service, key+"#previous", current.encode()); err != nil {
			return fmt.Errorf("keychain: write backup marker: %w", err)
		}
	}
	if usableCurrent && current.generation == "" {
		if err := keyring.Set(k.service, key+"#legacy-count", strconv.Itoa(current.count)); err != nil {
			return fmt.Errorf("keychain: preserve legacy count: %w", err)
		}
	}
	if err := keyring.Set(k.service, key, next.encode()); err != nil {
		return fmt.Errorf("keychain: publish generation: %w", err)
	}
	// Never remove legacy chunks during migration. Remove only a superseded
	// versioned generation after its replacement is published.
	if hadPrevious && usableCurrent && previous.generation != "" && previous.generation != current.generation {
		k.removeChunks(key, previous)
	}
	return nil
}

// Delete removes the current and previous published generations.
func (k *keychainStore) Delete(_ context.Context, key string) error {
	unlock, err := lockKeychain(k.service, key)
	if err != nil {
		return err
	}
	defer unlock()
	current, found, err := k.marker(key)
	if err != nil {
		return err
	}
	previous, hadPrevious, err := k.marker(key + "#previous")
	if err != nil {
		return err
	}
	legacy, hadLegacy, err := k.marker(key + "#legacy-count")
	if err != nil {
		return err
	}
	if err := keyring.Delete(k.service, key); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return err
	}
	if err := keyring.Delete(k.service, key+"#previous"); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return err
	}
	if err := keyring.Delete(k.service, key+"#legacy-count"); err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return err
	}
	if found {
		k.removeChunks(key, current)
	}
	if hadPrevious {
		k.removeChunks(key, previous)
	}
	if hadLegacy {
		k.removeChunks(key, legacy)
	}
	return nil
}
