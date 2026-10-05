package cache

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

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

	// The marker names one immutable generation and checks its digest.
	if c, err := keyring.Get("msauth-test", "acct"); err != nil {
		t.Fatal(err)
	} else if m, err := parseMarker(c); err != nil || m.count != 6 || m.generation == "" {
		t.Errorf("marker = %q, %v; want a six-chunk v2 marker", c, err)
	} else if _, err := keyring.Get("msauth-test", st.(*keychainStore).name("acct", m, 5)); err != nil {
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
	// The previous complete generation remains available after shrinking.
	previous, ok, err := st.(*keychainStore).marker("k#previous")
	if err != nil || !ok || previous.count != 4 {
		t.Fatalf("previous marker = %+v, %v, %v", previous, ok, err)
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

func TestKeychainStore_LegacyMigrationAndRecovery(t *testing.T) {
	keyring.MockInit()
	const service, key = "msauth-legacy-test", "account"
	ctx := context.Background()
	st := NewKeychainStoreWithService(service)
	legacy := bytes.Repeat([]byte("L"), 3*keychainChunkSize)
	for i := range 3 {
		if err := keyring.Set(service, chunkName(key, i), string(legacy[i*keychainChunkSize:(i+1)*keychainChunkSize])); err != nil {
			t.Fatal(err)
		}
	}
	if err := keyring.Set(service, key, "3"); err != nil {
		t.Fatal(err)
	}
	if got, err := st.Load(ctx, key); err != nil || !bytes.Equal(got, legacy) {
		t.Fatalf("legacy Load: len=%d, err=%v", len(got), err)
	}
	newBlob := bytes.Repeat([]byte("N"), 4*keychainChunkSize)
	if err := st.Save(ctx, key, newBlob); err != nil {
		t.Fatal(err)
	}
	// Migration must not erase the original credentials.
	if _, err := keyring.Get(service, chunkName(key, 2)); err != nil {
		t.Fatalf("legacy chunk removed: %v", err)
	}
	current, found, err := st.(*keychainStore).marker(key)
	if err != nil || !found {
		t.Fatalf("current marker: %v", err)
	}
	if err := keyring.Delete(service, st.(*keychainStore).name(key, current, 2)); err != nil {
		t.Fatal(err)
	}
	if got, err := st.Load(ctx, key); err != nil || !bytes.Equal(got, legacy) {
		t.Fatalf("recovery from missing chunk: len=%d, err=%v", len(got), err)
	}
	// Saving after fallback must keep the usable backup rather than copy the
	// corrupt current generation into the backup marker.
	if err := st.Save(ctx, key, []byte("repaired")); err != nil {
		t.Fatal(err)
	}
	backup, found, err := st.(*keychainStore).marker(key + "#previous")
	if err != nil || !found || backup.generation != "" || backup.count != 3 {
		t.Fatalf("backup after repair = %+v, %v, %v", backup, found, err)
	}
	if err := st.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := keyring.Get(service, chunkName(key, 2)); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("legacy credential chunk remains after logout: %v", err)
	}
}

func TestKeychainStore_UnpublishedGenerationDoesNotReplaceActive(t *testing.T) {
	keyring.MockInit()
	const service, key = "msauth-interrupted-test", "account"
	ctx := context.Background()
	st := NewKeychainStoreWithService(service)
	old := []byte("complete")
	if err := st.Save(ctx, key, old); err != nil {
		t.Fatal(err)
	}
	// Simulate a process dying after writing a new chunk but before publishing
	// the generation marker. No live item is touched by that write.
	if err := keyring.Set(service, key+"#00000000000000000000000000000000#0", "partial"); err != nil {
		t.Fatal(err)
	}
	if got, err := st.Load(ctx, key); err != nil || !bytes.Equal(got, old) {
		t.Fatalf("Load after interrupted write = %q, %v", got, err)
	}
}

func TestKeychainStore_LegacyMissingChunkIsReported(t *testing.T) {
	keyring.MockInit()
	const service, key = "msauth-broken-test", "account"
	if err := keyring.Set(service, key, "16"); err != nil {
		t.Fatal(err)
	}
	for i := range 16 {
		if i != 13 {
			if err := keyring.Set(service, chunkName(key, i), "data"); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := NewKeychainStoreWithService(service).Load(context.Background(), key); err == nil || !strings.Contains(err.Error(), "chunk 13/16") {
		t.Fatalf("missing chunk error = %v", err)
	}
}

func TestKeychainStore_ConcurrentSavesAndLoads(t *testing.T) {
	keyring.MockInit()
	st := NewKeychainStoreWithService("msauth-concurrent-test")
	ctx := context.Background()
	const workers = 8
	var wg sync.WaitGroup
	errors := make(chan error, workers)
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			blob := bytes.Repeat([]byte{byte('A' + i)}, 17*keychainChunkSize)
			if err := st.Save(ctx, "account", blob); err != nil {
				errors <- err
				return
			}
			got, err := st.Load(ctx, "account")
			if err != nil || len(got) != len(blob) || len(bytes.Trim(got, string(got[0]))) != 0 {
				errors <- fmt.Errorf("torn concurrent Load: len=%d, err=%v", len(got), err)
			}
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
}

func TestKeychainLockAcrossProcesses(t *testing.T) {
	const service, key = "msauth-process-test", "account"
	if os.Getenv("MSAUTH_LOCK_HELPER") == "1" {
		unlock, err := lockKeychain(service, key)
		if err != nil {
			t.Fatal(err)
		}
		defer unlock()
		fmt.Print("acquired")
		return
	}
	unlock, err := lockKeychain(service, key)
	if err != nil {
		t.Fatal(err)
	}
	cmdCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cmdCtx, os.Args[0], "-test.run=^TestKeychainLockAcrossProcesses$")
	cmd.Env = append(os.Environ(), "MSAUTH_LOCK_HELPER=1")
	result := make(chan error, 1)
	var output []byte
	go func() {
		var err error
		output, err = cmd.CombinedOutput()
		result <- err
	}()
	select {
	case err := <-result:
		unlock()
		t.Fatalf("child acquired lock early: %v, %q", err, output)
	case <-time.After(100 * time.Millisecond):
	}
	unlock()
	select {
	case err := <-result:
		if err != nil || !bytes.Contains(output, []byte("acquired")) {
			t.Fatalf("child lock: %v, %q", err, output)
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatal("child never acquired released lock")
	}
}
