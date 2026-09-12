package msauth

import (
	"context"
	"slices"
	"sync"
	"time"
)

// AccessToken is a delegated access token together with the metadata a caller
// needs to reason about it. [Authenticator.Token] returns only the bearer
// string, which is enough to send a request but not enough to decide whether a
// token is about to expire or which scopes consent actually granted.
type AccessToken struct {
	// Value is the bearer token to put in an Authorization header.
	Value string
	// ExpiresOn is when the token stops being accepted, in UTC.
	ExpiresOn time.Time
	// GrantedScopes are the scopes the service actually issued, which can be a
	// subset of those requested when the user declines part of the consent.
	GrantedScopes []string
}

// Expired reports whether the token is expired, treating anything within skew
// of expiry as already expired. A non-positive skew disables the margin.
func (t AccessToken) Expired(now time.Time, skew time.Duration) bool {
	if t.ExpiresOn.IsZero() {
		return false
	}
	if skew < 0 {
		skew = 0
	}
	return !now.Add(skew).Before(t.ExpiresOn)
}

// HasScope reports whether scope was granted. Comparison is case-insensitive
// because Entra echoes scopes back with inconsistent casing.
func (t AccessToken) HasScope(scope string) bool {
	return slices.ContainsFunc(t.GrantedScopes, func(granted string) bool {
		return equalFoldASCII(granted, scope)
	})
}

// TokenSource is a scope-bound token provider. Its method set is exactly
//
//	Token(ctx context.Context) (string, error)
//
// which is the shape Graph and other Microsoft REST clients expect, so it can
// be handed to them directly. [Authenticator.Token] cannot be used for that
// because its variadic options change its signature.
//
// A TokenSource caches the token it last obtained and reuses it until it is
// close to expiring, so calling it per request is the intended usage.
//
// The caching is not an optimization of something already cheap. The silent
// path underneath re-reads and decrypts the token cache on every call, which
// on a keychain-backed store costs hundreds of milliseconds of CPU; a command
// making twenty requests spent almost all of its time there rather than
// talking to the service.
//
// A TokenSource is safe for concurrent use. A refresh is taken under the lock
// so that concurrent callers wait for one refresh instead of each starting
// their own, which is the behavior that made the cost visible in the first
// place.
type TokenSource struct {
	auth   *Authenticator
	scopes []string

	mu     sync.Mutex
	cached AccessToken
	// fetch obtains a fresh token. It is a field so a test can count how
	// often a refresh actually happens, which is the only way to show that
	// concurrent callers share one instead of each starting their own.
	fetch func(context.Context) (AccessToken, error)
}

// tokenRefreshSkew is how long before expiry a cached token stops being
// reused. It has to exceed the time a request can spend in flight, or a token
// that looked valid when it was chosen can expire before it arrives.
const tokenRefreshSkew = 2 * time.Minute

// TokenSource returns a token provider bound to scopes. With no scopes it uses
// [Config.Scopes].
func (a *Authenticator) TokenSource(scopes ...string) *TokenSource {
	return &TokenSource{auth: a, scopes: slices.Clone(scopes)}
}

// Token returns a valid access token, refreshing silently as needed.
func (s *TokenSource) Token(ctx context.Context) (string, error) {
	token, err := s.TokenInfo(ctx)
	if err != nil {
		return "", err
	}
	return token.Value, nil
}

// TokenInfo returns the access token with its expiry and granted scopes,
// reusing the last one until it is close to expiring.
func (s *TokenSource) TokenInfo(ctx context.Context) (AccessToken, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cached.Value != "" && !s.cached.Expired(time.Now(), tokenRefreshSkew) {
		return s.cached, nil
	}

	token, err := s.refresh(ctx)
	if err != nil {
		return AccessToken{}, err
	}
	s.cached = token
	return token, nil
}

// refresh obtains a token from the authenticator, or from the test seam.
func (s *TokenSource) refresh(ctx context.Context) (AccessToken, error) {
	if s.fetch != nil {
		return s.fetch(ctx)
	}
	if len(s.scopes) == 0 {
		return s.auth.TokenInfo(ctx)
	}
	return s.auth.TokenInfo(ctx, WithScopes(s.scopes...))
}

// Invalidate discards the cached token so the next call fetches a fresh one.
//
// Expiry is handled without this. It exists for the case expiry cannot
// predict: a token revoked or a consent withdrawn while it is still within
// its stated lifetime, which the service reports as a 401 rather than in
// advance.
func (s *TokenSource) Invalidate() {
	s.mu.Lock()
	s.cached = AccessToken{}
	s.mu.Unlock()
}

// Scopes returns the scopes this source requests.
func (s *TokenSource) Scopes() []string { return slices.Clone(s.scopes) }

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range len(a) {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}
