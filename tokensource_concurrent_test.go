package msauth

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Every Graph request goes through a TokenSource, and a client making
// parallel requests hits one concurrently. These run under -race.

// The point of refreshing under the lock is that concurrent callers share one
// refresh. Without it, twenty parallel requests on a cold cache each start
// their own -- which is the thundering herd that made the keychain cost
// visible in the first place.
func TestConcurrentCallersShareOneRefresh(t *testing.T) {
	t.Parallel()
	var refreshes atomic.Int64

	source := &TokenSource{
		fetch: func(context.Context) (AccessToken, error) {
			refreshes.Add(1)
			// Wide enough that every goroutine is waiting before it returns.
			time.Sleep(20 * time.Millisecond)
			return AccessToken{Value: "fresh", ExpiresOn: time.Now().Add(time.Hour)}, nil
		},
	}

	const callers = 50
	var wg sync.WaitGroup
	values := make([]string, callers)
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := source.TokenInfo(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			values[i] = token.Value
		}()
	}
	wg.Wait()

	if got := refreshes.Load(); got != 1 {
		t.Errorf("%d callers caused %d refreshes, want 1", callers, got)
	}
	for i, value := range values {
		if value != "fresh" {
			t.Fatalf("caller %d got %q", i, value)
		}
	}
}

// A failed refresh must not be cached as a valid token, or one network blip
// would leave the source returning an empty bearer for the rest of its life.
func TestFailedRefreshIsNotCached(t *testing.T) {
	t.Parallel()
	var calls atomic.Int64
	wantErr := errors.New("network is down")

	source := &TokenSource{
		fetch: func(context.Context) (AccessToken, error) {
			if calls.Add(1) == 1 {
				return AccessToken{}, wantErr
			}
			return AccessToken{Value: "recovered", ExpiresOn: time.Now().Add(time.Hour)}, nil
		},
	}

	if _, err := source.TokenInfo(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("first call error = %v, want the fetch error", err)
	}
	token, err := source.TokenInfo(context.Background())
	if err != nil {
		t.Fatalf("second call failed: %v", err)
	}
	if token.Value != "recovered" {
		t.Errorf("token = %q, want the source to retry after a failure", token.Value)
	}
}

// Concurrent Token, TokenInfo and Invalidate must not race, and must never
// hand back a token the source has discarded.
func TestConcurrentUseIsSafe(t *testing.T) {
	t.Parallel()
	var issued atomic.Int64

	source := &TokenSource{
		fetch: func(context.Context) (AccessToken, error) {
			n := issued.Add(1)
			return AccessToken{
				Value:     "token",
				ExpiresOn: time.Now().Add(time.Duration(n) * time.Hour),
			}, nil
		},
	}

	var wg sync.WaitGroup
	for range 30 {
		wg.Add(3)
		go func() { defer wg.Done(); _, _ = source.Token(context.Background()) }()
		go func() { defer wg.Done(); _, _ = source.TokenInfo(context.Background()) }()
		go func() { defer wg.Done(); source.Invalidate() }()
	}
	wg.Wait()

	// Whatever the interleaving, the source still works afterwards.
	if _, err := source.Token(context.Background()); err != nil {
		t.Fatalf("unusable after concurrent use: %v", err)
	}
}

// An expired cached token must be replaced exactly once, not once per caller.
func TestExpiredTokenRefreshesOnceUnderLoad(t *testing.T) {
	t.Parallel()
	var refreshes atomic.Int64

	source := &TokenSource{
		fetch: func(context.Context) (AccessToken, error) {
			refreshes.Add(1)
			time.Sleep(10 * time.Millisecond)
			return AccessToken{Value: "new", ExpiresOn: time.Now().Add(time.Hour)}, nil
		},
	}
	// Already past its usable life.
	source.cached = AccessToken{Value: "old", ExpiresOn: time.Now().Add(-time.Minute)}

	var wg sync.WaitGroup
	for range 25 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := source.TokenInfo(context.Background())
			if err != nil {
				t.Error(err)
				return
			}
			if token.Value == "old" {
				t.Error("handed out an expired token")
			}
		}()
	}
	wg.Wait()

	if got := refreshes.Load(); got != 1 {
		t.Errorf("expired token caused %d refreshes, want 1", got)
	}
}
