package msauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"slices"
	"testing"
)

func TestNewPKCE_ChallengeIsS256OfVerifier(t *testing.T) {
	p := newPKCE()
	if p.verifier == "" || p.state == "" {
		t.Fatal("empty verifier/state")
	}
	sum := sha256.Sum256([]byte(p.verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if p.challenge != want {
		t.Errorf("challenge = %q, want %q", p.challenge, want)
	}
	if newPKCE().verifier == p.verifier {
		t.Error("verifier not random across calls")
	}
}

func TestWithOIDCScopes_AppendsAndDedups(t *testing.T) {
	got := withOIDCScopes([]string{"Mail.Read", "openid"})
	want := []string{"Mail.Read", "openid", "profile", "offline_access"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}

func TestBuildAuthorizeURL(t *testing.T) {
	p := pkce{verifier: "v", challenge: "chal", state: "st8"}
	raw := buildAuthorizeURL(
		"https://login.microsoftonline.com/consumers/",
		"client-123",
		"http://localhost:5000/",
		[]string{"Mail.Read"},
		p,
	)
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got, want := u.Path, "/consumers/oauth2/v2.0/authorize"; got != want {
		t.Errorf("path = %q, want %q", got, want)
	}
	q := u.Query()
	checks := map[string]string{
		"client_id":             "client-123",
		"response_type":         "code",
		"redirect_uri":          "http://localhost:5000/",
		"state":                 "st8",
		"code_challenge":        "chal",
		"code_challenge_method": "S256",
		"prompt":                "select_account",
	}
	for k, want := range checks {
		if got := q.Get(k); got != want {
			t.Errorf("query %s = %q, want %q", k, got, want)
		}
	}
	if scope := q.Get("scope"); scope != "Mail.Read openid profile offline_access" {
		t.Errorf("scope = %q", scope)
	}
}

func TestLoopbackListeners_BindsPort(t *testing.T) {
	v4, v6, port, err := loopbackListeners(context.Background())
	if err != nil {
		t.Fatalf("loopbackListeners: %v", err)
	}
	defer v4.Close()
	if v6 != nil {
		defer v6.Close()
	}
	if port <= 0 {
		t.Errorf("port = %d", port)
	}
}
