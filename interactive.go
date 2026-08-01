package msauth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
	"github.com/pkg/browser"
)

// loginInteractive runs Authorization-Code + PKCE over our own dual-stack
// loopback server (see loopback.go), then exchanges the code via MSAL. We do
// not use MSAL's AcquireTokenInteractive because its listener binds a single
// stack and breaks the redirect on macOS.
func (a *Authenticator) loginInteractive(ctx context.Context, lc loginConfig) (public.AuthResult, error) {
	p := newPKCE()

	v4, v6, port, err := loopbackListeners(ctx)
	if err != nil {
		return public.AuthResult{}, fmt.Errorf("msauth: %w", err)
	}
	// Own the listeners here; Close is idempotent-safe after srv.Shutdown and
	// guarantees no leak even on an immediate ctx cancellation race.
	defer func() { _ = v4.Close() }()
	if v6 != nil {
		defer func() { _ = v6.Close() }()
	}
	redirectURI := fmt.Sprintf("http://localhost:%d/", port)
	authzURL := buildAuthorizeURL(a.cfg.Authority, a.cfg.ClientID, redirectURI, lc.scopes, p)

	code, err := serveAndCapture(ctx, v4, v6, p.state, authzURL, openerOrDefault(lc.open))
	if err != nil {
		return public.AuthResult{}, err
	}
	return a.client.AcquireTokenByAuthCode(ctx, code, redirectURI, lc.scopes, public.WithChallenge(p.verifier))
}

// buildAuthorizeURL constructs the /authorize request for the auth-code + PKCE
// flow. Reserved OIDC scopes are appended so a refresh token is issued.
func buildAuthorizeURL(authority, clientID, redirectURI string, scopes []string, p pkce) string {
	q := url.Values{}
	q.Set("client_id", clientID)
	q.Set("response_type", "code")
	q.Set("redirect_uri", redirectURI)
	q.Set("scope", strings.Join(withOIDCScopes(scopes), " "))
	q.Set("state", p.state)
	q.Set("code_challenge", p.challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("prompt", "select_account")
	return strings.TrimRight(authority, "/") + "/oauth2/v2.0/authorize?" + q.Encode()
}

// withOIDCScopes appends the reserved OIDC scopes (deduped) needed for a
// refresh token, preserving the caller's scopes first.
func withOIDCScopes(scopes []string) []string {
	out := make([]string, 0, len(scopes)+3)
	seen := map[string]bool{}
	add := func(s string) {
		if s == "" || seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, s := range scopes {
		add(s)
	}
	for _, s := range []string{"openid", "profile", "offline_access"} {
		add(s)
	}
	return out
}

func openerOrDefault(open func(string) error) func(string) error {
	if open != nil {
		return open
	}
	return browser.OpenURL
}

// serveAndCapture opens the browser and serves both loopback listeners until it
// captures the auth code (state-validated), an OAuth error, timeout, or ctx
// cancellation.
func serveAndCapture(ctx context.Context, v4, v6 net.Listener, state, authzURL string, open func(string) error) (string, error) {
	codeCh := make(chan string, 1)
	errCh := make(chan error, 1)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("code") == "" && q.Get("error") == "" {
			w.WriteHeader(http.StatusNoContent) // favicon and other noise
			return
		}
		if q.Get("state") != state {
			http.Error(w, "state mismatch", http.StatusBadRequest)
			trySend(errCh, fmt.Errorf("msauth: state mismatch (possible CSRF)"))
			return
		}
		if e := q.Get("error"); e != "" {
			http.Error(w, e, http.StatusBadRequest)
			trySend(errCh, fmt.Errorf("msauth: authorization error: %s: %s", e, q.Get("error_description")))
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(successPage))
		trySendStr(codeCh, q.Get("code"))
	})

	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(v4) }()
	if v6 != nil {
		go func() { _ = srv.Serve(v6) }()
	}
	defer func() {
		sc, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(sc)
	}()

	if err := open(authzURL); err != nil {
		fmt.Fprintf(os.Stderr, "msauth: couldn't open browser (%v); visit:\n%s\n", err, authzURL)
	}

	select {
	case code := <-codeCh:
		return code, nil
	case err := <-errCh:
		return "", err
	case <-ctx.Done():
		return "", fmt.Errorf("msauth: login canceled or timed out: %w", ctx.Err())
	}
}

func trySend(ch chan<- error, err error) {
	select {
	case ch <- err:
	default:
	}
}

func trySendStr(ch chan<- string, s string) {
	select {
	case ch <- s:
	default:
	}
}
