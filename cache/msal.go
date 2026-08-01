package cache

import (
	"context"

	msalcache "github.com/AzureAD/microsoft-authentication-library-for-go/apps/cache"
)

// NewMSALAccessor adapts a [Store] to MSAL's cache.ExportReplace interface,
// partitioned under key. Pass the result to public.WithCache so that MSAL loads
// the cache before, and saves it after, each token operation — giving silent
// refresh across process restarts.
func NewMSALAccessor(store Store, key string) msalcache.ExportReplace {
	return &msalAccessor{store: store, key: key}
}

type msalAccessor struct {
	store Store
	key   string
}

// Replace loads the persisted cache into MSAL's in-memory cache. An absent key
// is not an error (fresh, never-logged-in state).
func (a *msalAccessor) Replace(ctx context.Context, cache msalcache.Unmarshaler, _ msalcache.ReplaceHints) error {
	blob, err := a.store.Load(ctx, a.key)
	if err != nil {
		return err
	}
	if len(blob) == 0 {
		return nil
	}
	return cache.Unmarshal(blob)
}

// Export writes MSAL's in-memory cache out to the Store.
func (a *msalAccessor) Export(ctx context.Context, cache msalcache.Marshaler, _ msalcache.ExportHints) error {
	blob, err := cache.Marshal()
	if err != nil {
		return err
	}
	return a.store.Save(ctx, a.key, blob)
}
