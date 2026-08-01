package msauth

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/albertocavalcante/msauth-go/msauthtest"
)

func TestIsTransient(t *testing.T) {
	cases := map[string]struct {
		err  error
		want bool
	}{
		"deadline":   {context.DeadlineExceeded, true},
		"canceled":   {context.Canceled, true},
		"net-error":  {&net.DNSError{Err: "no such host", IsTimeout: false}, true},
		"auth-error": {errors.New("invalid_grant: AADSTS70008"), false},
		"nil-wrap":   {errors.New("some other failure"), false},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if got := isTransient(tc.err); got != tc.want {
				t.Errorf("isTransient(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestNew_NilStore(t *testing.T) {
	if _, err := New(Config{}, nil); err == nil {
		t.Fatal("expected error for nil store")
	}
}

func TestNew_AppliesDefaults(t *testing.T) {
	a, err := New(Config{}, msauthtest.NewMemStore())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if a.cfg.ClientID != GraphCLIClientID {
		t.Errorf("ClientID = %q, want default %q", a.cfg.ClientID, GraphCLIClientID)
	}
	if a.cfg.Authority != DefaultAuthority {
		t.Errorf("Authority = %q, want %q", a.cfg.Authority, DefaultAuthority)
	}
	if a.cfg.LoginTimeout != DefaultLoginTimeout {
		t.Errorf("LoginTimeout = %v, want %v", a.cfg.LoginTimeout, DefaultLoginTimeout)
	}
	if a.key != "msauth:"+GraphCLIClientID {
		t.Errorf("cache key = %q", a.key)
	}
}

func TestTokenAndIdentity_LoginRequiredWhenEmpty(t *testing.T) {
	a, err := New(Config{Scopes: []string{"Mail.Read"}}, msauthtest.NewMemStore())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()

	if _, err := a.Token(ctx); !errors.Is(err, ErrLoginRequired) {
		t.Errorf("Token empty: got %v, want ErrLoginRequired", err)
	}
	if _, err := a.Identity(ctx); !errors.Is(err, ErrLoginRequired) {
		t.Errorf("Identity empty: got %v, want ErrLoginRequired", err)
	}
}

func TestNoScopes_GuardedOnLoginAndToken(t *testing.T) {
	a, err := New(Config{}, msauthtest.NewMemStore()) // no scopes configured
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ctx := context.Background()
	if _, err := a.Login(ctx); !errors.Is(err, ErrNoScopes) {
		t.Errorf("Login no-scopes: got %v, want ErrNoScopes", err)
	}
	if _, err := a.Token(ctx); !errors.Is(err, ErrNoScopes) {
		t.Errorf("Token no-scopes: got %v, want ErrNoScopes", err)
	}
	// An explicit per-call scope satisfies the guard (then hits login-required).
	if _, err := a.Token(ctx, WithScopes("Mail.Read")); errors.Is(err, ErrNoScopes) {
		t.Errorf("Token WithScopes should pass the no-scopes guard, got %v", err)
	}
}

func TestLogout_EmptyIsNoError(t *testing.T) {
	store := msauthtest.NewMemStore()
	a, err := New(Config{}, store)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := a.Logout(context.Background()); err != nil {
		t.Fatalf("Logout: %v", err)
	}
}

func TestConfig_WithDefaultsPreservesExplicit(t *testing.T) {
	c := Config{ClientID: "abc", Authority: "https://login.microsoftonline.com/common"}.withDefaults()
	if c.ClientID != "abc" {
		t.Errorf("ClientID overwritten: %q", c.ClientID)
	}
	if c.Authority != "https://login.microsoftonline.com/common" {
		t.Errorf("Authority overwritten: %q", c.Authority)
	}
	if c.cacheKey() != "msauth:abc" {
		t.Errorf("cacheKey = %q", c.cacheKey())
	}
}
