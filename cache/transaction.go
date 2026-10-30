package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// TransactionalStore coordinates complete cache operations across cooperating
// processes. The callback receives a nontransactional view that must not escape.
// Writes are serialized, not rolled back: a callback needing atomic publication
// must validate first and publish one blob with Save.
//
// Older writers and direct Store calls do not participate. Use an isolated
// namespace when such writers must coexist.
type TransactionalStore interface {
	Store
	Transact(context.Context, func(Store) error) error
}

// Transact uses store's transaction support when available. A custom Store
// without that interface runs the callback without cross-operation coordination.
func Transact(ctx context.Context, store Store, fn func(Store) error) error {
	if store == nil || fn == nil {
		return errors.New("cache: transaction requires a store and callback")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if tx, ok := store.(TransactionalStore); ok {
		return tx.Transact(ctx, fn)
	}
	return fn(store)
}

type transactionGate struct {
	token chan struct{}
	users int
}

var transactionGates = struct {
	sync.Mutex
	values map[string]*transactionGate
}{values: map[string]*transactionGate{}}

func acquireGate(ctx context.Context, path string) (func(), error) {
	transactionGates.Lock()
	gate := transactionGates.values[path]
	if gate == nil {
		gate = &transactionGate{token: make(chan struct{}, 1)}
		gate.token <- struct{}{}
		transactionGates.values[path] = gate
	}
	gate.users++
	transactionGates.Unlock()
	drop := func() {
		transactionGates.Lock()
		defer transactionGates.Unlock()
		gate.users--
		if gate.users == 0 {
			delete(transactionGates.values, path)
		}
	}
	select {
	case <-ctx.Done():
		drop()
		return nil, ctx.Err()
	case <-gate.token:
		return func() { gate.token <- struct{}{}; drop() }, nil
	}
}

type transactionView struct {
	Store
	ctx    context.Context
	active atomic.Bool
}

func (v *transactionView) check(ctx context.Context) error {
	if !v.active.Load() {
		return errors.New("cache: transaction view is closed")
	}
	if err := v.ctx.Err(); err != nil {
		return err
	}
	return ctx.Err()
}
func (v *transactionView) Load(ctx context.Context, key string) ([]byte, error) {
	if err := v.check(ctx); err != nil {
		return nil, err
	}
	return v.Store.Load(ctx, key)
}
func (v *transactionView) Save(ctx context.Context, key string, blob []byte) error {
	if err := v.check(ctx); err != nil {
		return err
	}
	return v.Store.Save(ctx, key, blob)
}
func (v *transactionView) Delete(ctx context.Context, key string) error {
	if err := v.check(ctx); err != nil {
		return err
	}
	return v.Store.Delete(ctx, key)
}

func runTransaction(ctx context.Context, store Store, path string, fn func(Store) error) error {
	if fn == nil {
		return errors.New("cache: nil transaction callback")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := ensurePrivateDir(dir); err != nil {
		return err
	}
	// Canonicalize directory aliases so the process gate shares the OS lock.
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return err
	}
	path = filepath.Join(dir, filepath.Base(path))
	unlock, err := acquireGate(ctx, path)
	if err != nil {
		return err
	}
	defer unlock()
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return errors.New("cache: transaction lock must be a regular file")
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		acquired, err := tryTransactionLock(f)
		if err != nil {
			return fmt.Errorf("cache: transaction lock: %w", err)
		}
		if acquired {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Millisecond):
		}
	}
	defer unlockTransactionFile(f)
	current, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !current.Mode().IsRegular() || !os.SameFile(opened, current) {
		return errors.New("cache: transaction lock changed")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	view := &transactionView{Store: store, ctx: ctx}
	view.active.Store(true)
	defer view.active.Store(false)
	return fn(view)
}

// Transact coordinates all client IDs and accounts within this keyring service.
// Its lock is separate from the per-blob locks used by Load/Save/Delete.
func (k *keychainStore) Transact(ctx context.Context, fn func(Store) error) error {
	base, err := os.UserCacheDir()
	if err != nil {
		return err
	}
	digest := sha256.Sum256([]byte(k.service))
	path := filepath.Join(base, "msauth-go", "transaction-locks", hex.EncodeToString(digest[:])+".lock")
	return runTransaction(ctx, k, path, fn)
}

// Transact coordinates all cache keys in this encrypted-file directory.
func (f *fileStore) Transact(ctx context.Context, fn func(Store) error) error {
	return runTransaction(ctx, f, filepath.Join(f.dir, ".msauth-transaction.lock"), fn)
}
