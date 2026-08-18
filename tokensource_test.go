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
