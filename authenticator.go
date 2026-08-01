package msauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"

	"github.com/albertocavalcante/msauth-go/cache"
)

// Authenticator signs a user in and hands out delegated access tokens, backed
// by a persistent token cache for silent refresh. It is safe for concurrent
// use by multiple goroutines within a single process (MSAL serializes cache
// access). It does not coordinate across processes sharing one file cache.
type Authenticator struct {
	cfg    Config
	client public.Client
	store  cache.Store
	key    string
}

// New builds an Authenticator for cfg, persisting the MSAL token cache in store.
// store must be non-nil (use an in-memory fake in tests, or a cache.Store impl).
func New(cfg Config, store cache.Store) (*Authenticator, error) {
	if store == nil {
		return nil, errors.New("msauth: nil store")
	}
	cfg = cfg.withDefaults()
	key := cfg.cacheKey()
	client, err := public.New(
		cfg.ClientID,
		public.WithAuthority(cfg.Authority),
		public.WithCache(cache.NewMSALAccessor(store, key)),
	)
	if err != nil {
		return nil, fmt.Errorf("msauth: new client: %w", err)
	}
	return &Authenticator{cfg: cfg, client: client, store: store, key: key}, nil
}

// LoginOption customizes a Login call.
type LoginOption func(*loginConfig)

type loginConfig struct {
	device bool
	scopes []string
	prompt func(message string)
	open   func(url string) error
}

// WithDevice selects the device-code flow instead of the interactive browser
// flow. Note: Microsoft rejects device-code for personal Microsoft Accounts;
// this is for work/school accounts.
func WithDevice() LoginOption { return func(c *loginConfig) { c.device = true } }

// WithLoginScopes overrides the default [Config.Scopes] for this login.
func WithLoginScopes(scopes ...string) LoginOption {
	return func(c *loginConfig) { c.scopes = scopes }
}

// WithPrompt sets a callback for device-code instructions (defaults to writing
// the MSAL message to stderr).
func WithPrompt(fn func(message string)) LoginOption {
	return func(c *loginConfig) { c.prompt = fn }
}

// WithBrowserOpener overrides how the interactive flow opens the browser
// (defaults to pkg/browser). Useful for headless tests.
func WithBrowserOpener(fn func(url string) error) LoginOption {
	return func(c *loginConfig) { c.open = fn }
}

// Login signs the user in interactively (or via device code) and returns their
// identity. The token cache is persisted as a side effect, so later Token calls
// can refresh silently. The call is bounded by [Config.LoginTimeout].
func (a *Authenticator) Login(ctx context.Context, opts ...LoginOption) (*Identity, error) {
	lc := loginConfig{scopes: a.cfg.Scopes}
	for _, o := range opts {
		o(&lc)
	}
	if len(lc.scopes) == 0 {
		return nil, ErrNoScopes
	}

	var (
		res public.AuthResult
		err error
	)
	if lc.device {
		// Device-code is bounded by the code's own expiry (~15m), which MSAL
		// honors from the caller ctx. Do NOT impose the short interactive
		// LoginTimeout — the user must switch devices to enter the code.
		res, err = a.loginDevice(ctx, lc)
	} else {
		ictx, cancel := context.WithTimeout(ctx, a.cfg.LoginTimeout)
		defer cancel()
		res, err = a.loginInteractive(ictx, lc)
	}
	if err != nil {
		return nil, err
	}
	return &Identity{
		Username:      res.Account.PreferredUsername,
		Name:          res.IDToken.Name,
		HomeAccountID: res.Account.HomeAccountID,
	}, nil
}

// TokenOption customizes a Token call.
type TokenOption func(*tokenConfig)

type tokenConfig struct {
	scopes []string
}

// WithScopes overrides the default [Config.Scopes] for this token request.
// MSAL caches tokens per scope set, so requesting different scopes for a
// resource is fine on one cached account.
func WithScopes(scopes ...string) TokenOption {
	return func(c *tokenConfig) { c.scopes = scopes }
}

// Token returns a valid delegated access token for the cached account,
// refreshing silently as needed. It returns [ErrLoginRequired] (joined with the
// underlying cause) when there is no usable cached account.
func (a *Authenticator) Token(ctx context.Context, opts ...TokenOption) (string, error) {
	tc := tokenConfig{scopes: a.cfg.Scopes}
	for _, o := range opts {
		o(&tc)
	}
	if len(tc.scopes) == 0 {
		// Empty scopes cause a silent cache miss in MSAL's silent path, which
		// would otherwise be misreported as ErrLoginRequired.
		return "", ErrNoScopes
	}
	acct, err := a.account(ctx)
	if err != nil {
		return "", err
	}
	res, err := a.client.AcquireTokenSilent(ctx, tc.scopes, public.WithSilentAccount(acct))
	if err != nil {
		if isTransient(err) {
			// Network/timeout/cancellation: a retry may succeed. Do NOT signal
			// ErrLoginRequired, or callers would force a needless (and offline-
			// doomed) re-login on a transient blip.
			return "", fmt.Errorf("msauth: silent token refresh failed: %w", err)
		}
		// Otherwise the cached grant is unusable (expired/revoked/consent) →
		// re-login is genuinely required; keep the cause inspectable.
		return "", errors.Join(ErrLoginRequired, err)
	}
	return res.AccessToken, nil
}

// isTransient reports whether err is a transient network/context failure rather
// than an auth/grant failure that requires re-login.
func isTransient(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne)
}

// Identity returns the cached user's identity without a network call. Name is
// empty here (it comes from the login-time id token). Returns
// [ErrLoginRequired] when nothing is cached.
func (a *Authenticator) Identity(ctx context.Context) (*Identity, error) {
	acct, err := a.account(ctx)
	if err != nil {
		return nil, err
	}
	return &Identity{Username: acct.PreferredUsername, HomeAccountID: acct.HomeAccountID}, nil
}

// Logout removes cached accounts and deletes the persisted cache blob. The blob
// is keyed per client id and holds every account signed in under it, so Logout
// signs out ALL accounts for this Authenticator's client id, not just the
// preferred one.
func (a *Authenticator) Logout(ctx context.Context) error {
	if accts, err := a.client.Accounts(ctx); err == nil {
		// Best-effort in-memory cleanup; the durable source of truth is the
		// persisted blob deleted below, and a fresh process starts clean.
		for i := range accts {
			_ = a.client.RemoveAccount(ctx, accts[i])
		}
	}
	return a.store.Delete(ctx, a.key)
}

// account selects the preferred cached account, or the first one.
func (a *Authenticator) account(ctx context.Context) (public.Account, error) {
	accts, err := a.client.Accounts(ctx)
	if err != nil {
		return public.Account{}, fmt.Errorf("msauth: list accounts: %w", err)
	}
	if len(accts) == 0 {
		return public.Account{}, ErrLoginRequired
	}
	if a.cfg.Account != "" {
		for i := range accts {
			if strings.EqualFold(accts[i].PreferredUsername, a.cfg.Account) {
				return accts[i], nil
			}
		}
		// A specific account was requested but isn't cached: don't silently
		// hand back a different account's tokens.
		return public.Account{}, fmt.Errorf("%w: no cached account matches %q", ErrLoginRequired, a.cfg.Account)
	}
	return accts[0], nil
}
