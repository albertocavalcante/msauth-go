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

// ErrInvalidAccountRef reports an incomplete or conflicting exact selector.
var ErrInvalidAccountRef = errors.New("msauth: invalid exact account reference")

// ErrAccountMismatch reports a conflicting authority or authenticated identity.
var ErrAccountMismatch = errors.New("msauth: account context mismatch")

// ErrAccountAmbiguous reports multiple cache entries matching an exact selector.
var ErrAccountAmbiguous = errors.New("msauth: exact account reference is ambiguous")

// ErrAccountRemovalUnsafe reports that MSAL cannot guarantee tenant-scoped
// removal. Bound authenticators return it before IO. Only an isolated store
// owner may explicitly use an unbound authenticator to clear that namespace.
var ErrAccountRemovalUnsafe = errors.New("msauth: exact-bound account removal is unsupported")

// ErrBoundLogin reports interactive login on an exact-bound authenticator.
// Stage login with New and a separate Store, validate LoginAccount's result,
// then publish that candidate instead of modifying the existing connection.
var ErrBoundLogin = errors.New("msauth: exact-bound account requires staged login")
