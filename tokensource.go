package msauth

import (
	"context"
	"slices"
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
// A TokenSource holds no token state of its own: every call goes through the
// authenticator's silent-refresh path, which is cached, so calling it per
// request is the intended usage.
type TokenSource struct {
	auth   *Authenticator
	scopes []string
}

// TokenSource returns a token provider bound to scopes. With no scopes it uses
// [Config.Scopes].
func (a *Authenticator) TokenSource(scopes ...string) *TokenSource {
	return &TokenSource{auth: a, scopes: slices.Clone(scopes)}
}

// Token returns a valid access token, refreshing silently as needed.
func (s *TokenSource) Token(ctx context.Context) (string, error) {
	if len(s.scopes) == 0 {
		return s.auth.Token(ctx)
	}
	return s.auth.Token(ctx, WithScopes(s.scopes...))
}

// TokenInfo returns the access token with its expiry and granted scopes.
func (s *TokenSource) TokenInfo(ctx context.Context) (AccessToken, error) {
	if len(s.scopes) == 0 {
		return s.auth.TokenInfo(ctx)
	}
	return s.auth.TokenInfo(ctx, WithScopes(s.scopes...))
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
