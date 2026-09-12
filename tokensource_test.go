package msauth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/albertocavalcante/msauth-go/msauthtest"
)

// graphTokenSource mirrors the interface Microsoft Graph clients accept. The
// assertion is the point of TokenSource: Authenticator.Token is variadic and
// therefore does not satisfy it, so callers would otherwise hand-write an
// adapter closure at every integration point.
type graphTokenSource interface {
	Token(ctx context.Context) (string, error)
}

var _ graphTokenSource = (*TokenSource)(nil)

func TestTokenSourceSatisfiesGraphInterface(t *testing.T) {
	a, err := New(Config{Scopes: []string{"Mail.Read"}}, msauthtest.NewMemStore())
	if err != nil {
		t.Fatal(err)
	}
	var source graphTokenSource = a.TokenSource()
	if _, err := source.Token(context.Background()); !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("Token() = %v, want ErrLoginRequired on an empty cache", err)
	}
}

func TestTokenSourceScopesAreCopied(t *testing.T) {
	a, err := New(Config{Scopes: []string{"Mail.Read"}}, msauthtest.NewMemStore())
	if err != nil {
		t.Fatal(err)
	}
	requested := []string{"Mail.ReadWrite", "Mail.Send"}
	source := a.TokenSource(requested...)

	// Mutating the caller's slice must not change what the source requests.
	requested[0] = "Directory.ReadWrite.All"
	got := source.Scopes()
	if got[0] != "Mail.ReadWrite" || got[1] != "Mail.Send" {
		t.Fatalf("Scopes() = %v", got)
	}

	// And mutating the returned slice must not change it either.
	got[0] = "mutated"
	if again := source.Scopes(); again[0] != "Mail.ReadWrite" {
		t.Fatalf("Scopes() leaked internal state: %v", again)
	}
}

func TestTokenSourceWithoutScopesFallsBackToConfig(t *testing.T) {
	a, err := New(Config{}, msauthtest.NewMemStore()) // no scopes configured
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.TokenSource().Token(context.Background()); !errors.Is(err, ErrNoScopes) {
		t.Fatalf("Token() = %v, want ErrNoScopes", err)
	}
	if _, err := a.TokenSource().TokenInfo(context.Background()); !errors.Is(err, ErrNoScopes) {
		t.Fatalf("TokenInfo() = %v, want ErrNoScopes", err)
	}
}

func TestTokenInfoPropagatesLoginRequired(t *testing.T) {
	a, err := New(Config{Scopes: []string{"Mail.Read"}}, msauthtest.NewMemStore())
	if err != nil {
		t.Fatal(err)
	}
	token, err := a.TokenInfo(context.Background())
	if !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("TokenInfo() = %v, want ErrLoginRequired", err)
	}
	if token.Value != "" || !token.ExpiresOn.IsZero() || token.GrantedScopes != nil {
		t.Fatalf("TokenInfo() returned %+v on error, want zero value", token)
	}
}

func TestAccessTokenExpired(t *testing.T) {
	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

	tests := []struct {
		name      string
		expiresOn time.Time
		skew      time.Duration
		want      bool
	}{
		{"future beyond skew", now.Add(10 * time.Minute), time.Minute, false},
		{"inside skew window", now.Add(30 * time.Second), time.Minute, true},
		{"already past", now.Add(-time.Second), 0, true},
		{"exactly now", now, 0, true},
		{"unset expiry never expires", time.Time{}, time.Minute, false},
		{"negative skew treated as zero", now.Add(time.Second), -time.Hour, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := AccessToken{ExpiresOn: tt.expiresOn}
			if got := token.Expired(now, tt.skew); got != tt.want {
				t.Fatalf("Expired() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAccessTokenHasScope(t *testing.T) {
	token := AccessToken{GrantedScopes: []string{"Mail.Read", "User.Read"}}
	if !token.HasScope("mail.read") {
		t.Fatal("HasScope should match case-insensitively")
	}
	if !token.HasScope("Mail.Read") {
		t.Fatal("HasScope should match exactly")
	}
	if token.HasScope("Mail.Send") {
		t.Fatal("HasScope matched a scope that was not granted")
	}
	if token.HasScope("Mail.Rea") {
		t.Fatal("HasScope matched a prefix")
	}
}

// The silent path re-reads and decrypts the token cache on every call, so a
// source that did not cache made a command's cost scale with its request
// count rather than its work.
func TestTokenSourceReusesAValidToken(t *testing.T) {
	t.Parallel()
	source := &TokenSource{}
	source.cached = AccessToken{
		Value:     "cached",
		ExpiresOn: time.Now().Add(time.Hour),
	}

	// No authenticator is set, so any call that does not use the cache will
	// panic rather than quietly fetch.
	for range 100 {
		token, err := source.TokenInfo(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if token.Value != "cached" {
			t.Fatalf("token = %q, want the cached one", token.Value)
		}
	}
}

// A token within the refresh margin must not be reused: a request can be in
// flight longer than the time left on it.
func TestTokenSourceRefreshesNearExpiry(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		expiresIn time.Duration
		wantReuse bool
	}{
		{"plenty of time", time.Hour, true},
		{"just outside the margin", tokenRefreshSkew + time.Minute, true},
		{"inside the margin", tokenRefreshSkew / 2, false},
		{"already expired", -time.Minute, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			token := AccessToken{Value: "v", ExpiresOn: time.Now().Add(tc.expiresIn)}
			reusable := !token.Expired(time.Now(), tokenRefreshSkew)
			if reusable != tc.wantReuse {
				t.Errorf("reusable = %v, want %v", reusable, tc.wantReuse)
			}
		})
	}
}

func TestTokenSourceInvalidateForcesARefetch(t *testing.T) {
	t.Parallel()
	source := &TokenSource{}
	source.cached = AccessToken{Value: "cached", ExpiresOn: time.Now().Add(time.Hour)}

	if _, err := source.TokenInfo(context.Background()); err != nil {
		t.Fatal(err)
	}
	source.Invalidate()

	// With the cache cleared and no authenticator, the next call must try to
	// fetch rather than return the discarded token.
	defer func() {
		if recover() == nil {
			t.Error("Invalidate did not clear the cached token")
		}
	}()
	_, _ = source.TokenInfo(context.Background())
}
