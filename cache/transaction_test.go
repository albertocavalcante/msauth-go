package cache

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
)

func TestKeychainTransactionsCoordinateService(t *testing.T) {
	keyring.MockInit()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	const service = "msauth-transaction-test"
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- Transact(ctx, NewKeychainStoreWithService(service), func(view Store) error {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
			return view.Save(ctx, "first-client", []byte("synthetic"))
		})
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	waiting, stop := context.WithTimeout(ctx, 40*time.Millisecond)
	defer stop()
	if err := Transact(waiting, NewKeychainStoreWithService(service), func(Store) error {
		return errors.New("must not run for another client ID in this service")
	}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("service lock bypassed: %v", err)
	}
	// An unrelated service does not wait behind this application.
	if err := Transact(ctx, NewKeychainStoreWithService(service+"-other"), func(Store) error { return nil }); err != nil {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	body, err := NewKeychainStoreWithService(service).Load(ctx, "first-client")
	if err != nil || string(body) != "synthetic" {
		t.Fatalf("transaction did not publish through keyring: %q %v", body, err)
	}
}

func TestTransactionCancellationAndViewLifetime(t *testing.T) {
	store := NewFileStore(t.TempDir())
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	var expired Store
	go func() {
		done <- Transact(t.Context(), store, func(view Store) error {
			expired = view
			if _, ok := view.(TransactionalStore); ok {
				return errors.New("nested transaction interface leaked")
			}
			close(entered)
			<-release
			return view.Save(t.Context(), "first", []byte("complete"))
		})
	}()
	<-entered
	ctx, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
	defer cancel()
	called := false
	err := Transact(ctx, NewFileStore(store.(*fileStore).dir), func(Store) error {
		called = true
		return nil
	})
	if !errors.Is(err, context.DeadlineExceeded) || called {
		t.Fatalf("waiting cancellation: %v called=%v", err, called)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := expired.Save(t.Context(), "later", []byte("invalid")); err == nil {
		t.Fatal("transaction view remained usable after release")
	}
	want := errors.New("callback failed")
	if err := Transact(t.Context(), store, func(Store) error { return want }); !errors.Is(err, want) {
		t.Fatalf("callback cause lost: %v", err)
	}
	if err := Transact(t.Context(), store, func(Store) error { return nil }); err != nil {
		t.Fatalf("lock not released after failure: %v", err)
	}
}

func TestTransactionProcessHelper(t *testing.T) {
	dir := os.Getenv("MSAUTH_TEST_TRANSACTION_DIR")
	if dir == "" {
		return
	}
	store := NewFileStore(dir)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if os.Getenv("MSAUTH_TEST_TRANSACTION_HOLD") == "1" {
		err := Transact(ctx, store, func(Store) error {
			if err := os.WriteFile(filepath.Join(dir, "ready"), []byte("ready"), 0o600); err != nil {
				return err
			}
			<-ctx.Done()
			return ctx.Err()
		})
		if err != nil {
			t.Fatal(err)
		}
		return
	}
	for range 15 {
		if err := Transact(ctx, store, func(view Store) error {
			body, err := view.Load(ctx, "counter")
			if err != nil {
				return err
			}
			n := 0
			if len(body) != 0 {
				n, err = strconv.Atoi(string(body))
				if err != nil {
					return err
				}
			}
			time.Sleep(time.Millisecond)
			return view.Save(ctx, "counter", []byte(strconv.Itoa(n+1)))
		}); err != nil {
			t.Fatal(err)
		}
	}
}

func helperProcess(ctx context.Context, dir string, hold bool) *exec.Cmd {
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestTransactionProcessHelper$")
	mode := "0"
	if hold {
		mode = "1"
	}
	cmd.Env = append(os.Environ(), "MSAUTH_TEST_TRANSACTION_DIR="+dir, "MSAUTH_TEST_TRANSACTION_HOLD="+mode)
	return cmd
}

func TestTransactionsAcrossProcesses(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	dir := t.TempDir()
	cmds := []*exec.Cmd{helperProcess(ctx, dir, false), helperProcess(ctx, dir, false), helperProcess(ctx, dir, false)}
	for _, cmd := range cmds {
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
	}
	for _, cmd := range cmds {
		if err := cmd.Wait(); err != nil {
			t.Fatal(err)
		}
	}
	body, err := NewFileStore(dir).Load(ctx, "counter")
	if err != nil || string(body) != "45" {
		t.Fatalf("cross-process update lost: %q %v", body, err)
	}
}

func TestTransactionProcessDeathReleasesLock(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	dir := t.TempDir()
	cmd := helperProcess(ctx, dir, true)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	for {
		if _, err := os.Stat(filepath.Join(dir, "ready")); err == nil {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-time.After(5 * time.Millisecond):
		}
	}
	waiting, stop := context.WithTimeout(ctx, 40*time.Millisecond)
	defer stop()
	if err := Transact(waiting, NewFileStore(dir), func(Store) error { return errors.New("must not run") }); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("OS lock did not respect waiting cancellation: %v", err)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if err := Transact(ctx, NewFileStore(dir), func(view Store) error {
		return view.Save(ctx, "after-death", []byte("valid"))
	}); err != nil {
		t.Fatalf("dead process retained lock: %v", err)
	}
}

func TestFirstFileWritersShareCompleteEncryptionKey(t *testing.T) {
	dir := t.TempDir()
	const writers = 25
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := NewFileStore(dir).Save(t.Context(), strconv.Itoa(i), []byte("synthetic")); err != nil {
				t.Error(err)
			}
		}()
	}
	close(start)
	wg.Wait()
	for i := range writers {
		body, err := NewFileStore(dir).Load(t.Context(), strconv.Itoa(i))
		if err != nil || string(body) != "synthetic" {
			t.Fatalf("first-writer key race for %d: %q %v", i, body, err)
		}
	}
}
