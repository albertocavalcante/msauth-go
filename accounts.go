package msauth

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"

	"github.com/albertocavalcante/msauth-go/cache"
)

// personalTenantID is Microsoft's documented personal-account tenant. Its
// supported authority alias is consumers; MSAL forbids overriding that alias
// through WithTenantID. See https://learn.microsoft.com/en-us/entra/msal/android/accounts-overview.
const personalTenantID = "9188040d-6c67-4c5b-b112-36a304b66dad"

// AccountRef identifies one account in one resource tenant. Opaque IDs are
// compared exactly; Environment is a case-insensitive authority hostname.
// LocalAccountID may be empty when the cache does not provide it. TenantID is
// the resource tenant, never a tenant inferred from HomeAccountID.
type AccountRef struct {
	HomeAccountID  string
	Environment    string
	TenantID       string
	LocalAccountID string
}

// AccountInfo is safe account metadata, without tokens or raw MSAL values.
// CacheRealm records the cache's authority path, which can be a discovery alias
// such as common rather than the identity's resource tenant. Accounts and
// unbound Account leave Ref.TenantID empty for such aliases; LoginAccount fills
// it from the login result's ID-token tenant claim.
type AccountInfo struct {
	Ref        AccountRef
	Username   string
	Name       string
	CacheRealm string
}

// NewForAccount creates an authenticator bound to an exact account reference.
// It preserves New's cache layout but never falls back to another account.
// Config.Account must be empty. A configured discovery authority is pinned to
// ref.TenantID; a different environment or specific tenant is rejected.
// Personal accounts use the consumers authority. Construction does no IO.
//
// A bound authenticator supports silent acquisition and metadata. Login returns
// ErrBoundLogin and Logout returns ErrAccountRemovalUnsafe before IO.
// Stage reauthentication using New and a separate
// Store, call LoginAccount, validate its Ref, then publish the candidate store.
func NewForAccount(cfg Config, store cache.Store, ref AccountRef) (*Authenticator, error) {
	if err := validateAccountRef(ref); err != nil {
		return nil, err
	}
	if cfg.Account != "" {
		return nil, fmt.Errorf("%w: Config.Account conflicts with an exact reference", ErrInvalidAccountRef)
	}
	authority, err := accountAuthority(cfg.Authority, ref)
	if err != nil {
		return nil, err
	}
	cfg.Authority = authority
	a, err := New(cfg, store)
	if err != nil {
		return nil, err
	}
	a.bound = &ref
	return a, nil
}

// Accounts lists cached account metadata without acquiring tokens or changing
// the cache. The result is sorted by reference for deterministic discovery.
// It lists all accounts in this Store/client ID, including on a bound instance.
func (a *Authenticator) Accounts(ctx context.Context) ([]AccountInfo, error) {
	return withCacheValue(ctx, a, func(current *Authenticator) ([]AccountInfo, error) { return current.accounts(ctx) })
}

func (a *Authenticator) accounts(ctx context.Context) ([]AccountInfo, error) {
	accounts, err := a.client.Accounts(ctx)
	if err != nil {
		return nil, fmt.Errorf("msauth: list accounts: %w", err)
	}
	infos := make([]AccountInfo, 0, len(accounts))
	for _, account := range accounts {
		infos = append(infos, cachedAccountInfo(account))
	}
	slices.SortFunc(infos, compareAccounts)
	return infos, nil
}

// Account returns the selected cached account's safe metadata without acquiring
// a token. On a bound instance Ref is the exact configured reference; CacheRealm
// still describes the underlying cache entry.
func (a *Authenticator) Account(ctx context.Context) (*AccountInfo, error) {
	return withCacheValue(ctx, a, func(current *Authenticator) (*AccountInfo, error) { return current.accountInfo(ctx) })
}

func (a *Authenticator) accountInfo(ctx context.Context) (*AccountInfo, error) {
	account, err := a.account(ctx)
	if err != nil {
		return nil, err
	}
	info := cachedAccountInfo(account)
	if a.bound != nil {
		info.Ref = *a.bound
	}
	return &info, nil
}

// LoginAccount performs Login and returns the full account context. Like Login,
// it persists credentials before returning; use a separate candidate Store when
// adding or reauthenticating a managed account. A missing or conflicting tenant
// claim returns ErrAccountMismatch, leaving the candidate for its owner to
// discard. A bound instance returns ErrBoundLogin before any login side effect.
func (a *Authenticator) LoginAccount(ctx context.Context, opts ...LoginOption) (*AccountInfo, error) {
	result, err := a.login(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return loginAccountInfo(result)
}

func cachedAccountInfo(account public.Account) AccountInfo {
	tenant := account.Realm
	if strings.EqualFold(tenant, "consumers") {
		tenant = personalTenantID
	} else if isDiscoveryTenant(tenant) {
		tenant = ""
	}
	return AccountInfo{
		Ref: AccountRef{
			HomeAccountID:  account.HomeAccountID,
			Environment:    account.Environment,
			TenantID:       tenant,
			LocalAccountID: account.LocalAccountID,
		},
		Username:   account.PreferredUsername,
		Name:       account.Name,
		CacheRealm: account.Realm,
	}
}

func loginAccountInfo(result public.AuthResult) (*AccountInfo, error) {
	info := cachedAccountInfo(result.Account)
	tenant := result.IDToken.TenantID
	if tenant == "" || isDiscoveryTenant(tenant) ||
		(info.Ref.TenantID != "" && info.Ref.TenantID != tenant) {
		return nil, ErrAccountMismatch
	}
	info.Ref.TenantID = tenant
	info.Name = result.IDToken.Name
	if err := validateAccountRef(info.Ref); err != nil {
		return nil, errors.Join(ErrAccountMismatch, err)
	}
	return &info, nil
}

func compareAccounts(a, b AccountInfo) int {
	for _, pair := range [][2]string{
		{a.Ref.HomeAccountID, b.Ref.HomeAccountID},
		{strings.ToLower(a.Ref.Environment), strings.ToLower(b.Ref.Environment)},
		{a.Ref.TenantID, b.Ref.TenantID},
		{a.Ref.LocalAccountID, b.Ref.LocalAccountID},
		{a.CacheRealm, b.CacheRealm},
	} {
		if order := cmp.Compare(pair[0], pair[1]); order != 0 {
			return order
		}
	}
	return 0
}

func validateAccountRef(ref AccountRef) error {
	if !cleanIdentityField(ref.HomeAccountID) || !cleanIdentityField(ref.Environment) ||
		!cleanIdentityField(ref.TenantID) || isDiscoveryTenant(ref.TenantID) {
		return ErrInvalidAccountRef
	}
	if ref.LocalAccountID != "" && !cleanIdentityField(ref.LocalAccountID) {
		return ErrInvalidAccountRef
	}
	if strings.ContainsAny(ref.Environment, "/\\:@?#%") || strings.ContainsAny(ref.TenantID, "/\\:@?#%") {
		return ErrInvalidAccountRef
	}
	return nil
}

func cleanIdentityField(value string) bool {
	if value == "" || strings.TrimSpace(value) != value {
		return false
	}
	return !strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r == 0x7f })
}

func isDiscoveryTenant(tenant string) bool {
	return strings.EqualFold(tenant, "common") || strings.EqualFold(tenant, "organizations") || strings.EqualFold(tenant, "consumers")
}

func accountAuthority(configured string, ref AccountRef) (string, error) {
	if configured != "" {
		u, err := url.Parse(configured)
		if err != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" ||
			u.Fragment != "" || !strings.EqualFold(u.Host, ref.Environment) || u.RawPath != "" {
			return "", fmt.Errorf("%w: authority environment does not match", ErrAccountMismatch)
		}
		tenant := strings.TrimPrefix(u.Path, "/")
		alias := strings.ToLower(tenant)
		if tenant == "" || strings.Contains(tenant, "/") ||
			(tenant != ref.TenantID && !isDiscoveryTenant(tenant)) ||
			(alias == "consumers" && ref.TenantID != personalTenantID) ||
			(alias == "organizations" && ref.TenantID == personalTenantID) {
			return "", fmt.Errorf("%w: authority tenant does not match", ErrAccountMismatch)
		}
	}
	tenant := ref.TenantID
	if tenant == personalTenantID {
		tenant = "consumers"
	}
	return "https://" + ref.Environment + "/" + tenant, nil
}

func selectExactAccount(accounts []public.Account, ref AccountRef) (public.Account, error) {
	var exact, discovery []public.Account
	for _, account := range accounts {
		if !sameAccountIdentity(account, ref) {
			continue
		}
		alias := strings.ToLower(account.Realm)
		if account.Realm == ref.TenantID || (alias == "consumers" && ref.TenantID == personalTenantID) {
			exact = append(exact, account)
		} else if (alias == "common" || alias == "organizations") && ref.LocalAccountID != "" {
			// Discovery realms are not tenant proof. The exact local/home IDs
			// select the identity; the subsequent token call pins its tenant.
			discovery = append(discovery, account)
		}
	}
	if len(exact) == 0 {
		exact = discovery
	}
	if len(exact) > 1 {
		return public.Account{}, ErrAccountAmbiguous
	}
	if len(exact) == 0 {
		return public.Account{}, fmt.Errorf("%w: no exact cached account", ErrLoginRequired)
	}
	return exact[0], nil
}

func sameAccountIdentity(account public.Account, ref AccountRef) bool {
	return account.HomeAccountID == ref.HomeAccountID && strings.EqualFold(account.Environment, ref.Environment) &&
		(ref.LocalAccountID == "" || account.LocalAccountID == ref.LocalAccountID)
}

func (a *Authenticator) checkTokenAccount(result public.AuthResult) error {
	if result.IDToken.TenantID != "" && result.IDToken.TenantID != a.bound.TenantID {
		return ErrAccountMismatch
	}
	// MSAL can refresh without a new ID token and return no account metadata.
	// Its request was already bound to the selected home identity and tenant.
	// Validate returned metadata when present, never substitute another account.
	if result.Account.HomeAccountID == "" && result.Account.Environment == "" &&
		result.Account.Realm == "" && result.Account.LocalAccountID == "" {
		return nil
	}
	if !sameAccountIdentity(result.Account, *a.bound) {
		return ErrAccountMismatch
	}
	if result.Account.Realm != a.bound.TenantID &&
		(!strings.EqualFold(result.Account.Realm, "consumers") || a.bound.TenantID != personalTenantID) {
		return ErrAccountMismatch
	}
	return nil
}
