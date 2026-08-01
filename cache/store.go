// Package cache provides persistent storage for the MSAL token cache used by
// msauth. The [Store] interface is a small key/opaque-blob contract; two
// implementations ship: a macOS Keychain store ([NewKeychainStore]) and an
// AES-256-GCM encrypted-file store ([NewFileStore]) for headless/Linux use.
//
// The stored blob is MSAL's serialized token cache, which contains the refresh
// token. Treat it as a secret: the Keychain store relies on OS ACLs; the file
// store encrypts at rest and writes 0600 files.
package cache

import "context"

// Store persists opaque cache blobs by key. Implementations must be safe for
// concurrent use. Load returns (nil, nil) when the key is absent (not an
// error).
type Store interface {
	Load(ctx context.Context, key string) ([]byte, error)
	Save(ctx context.Context, key string, blob []byte) error
	Delete(ctx context.Context, key string) error
}
