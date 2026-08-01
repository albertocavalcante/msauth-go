package msauth

import "errors"

// ErrLoginRequired is returned by [Authenticator.Token] and
// [Authenticator.Identity] when there is no usable cached account (never logged
// in, cache wiped, or the refresh token has expired/been revoked). Callers
// should prompt the user to run login. It is joined with the underlying MSAL
// error when a silent refresh fails, so errors.Is(err, ErrLoginRequired) is
// true while the cause remains inspectable.
var ErrLoginRequired = errors.New("msauth: login required")

// ErrNoScopes is returned by Login and Token when no delegated scopes are set
// (neither Config.Scopes nor a WithScopes/WithLoginScopes option). MSAL rejects
// empty scopes with an opaque message on login and, worse, silently misses the
// cache on Token; this turns that into a clear, actionable error.
var ErrNoScopes = errors.New("msauth: no scopes requested (set Config.Scopes or use WithScopes/WithLoginScopes)")
