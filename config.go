package msauth

import "time"

const (
	// DefaultAuthority targets personal Microsoft Accounts only. Use
	// "https://login.microsoftonline.com/common" to also accept work/school
	// accounts.
	DefaultAuthority = "https://login.microsoftonline.com/consumers"

	// GraphCLIClientID is Microsoft's well-known first-party public client,
	// "Microsoft Graph Command Line Tools". It has http://localhost registered
	// and grants dynamic delegated Microsoft Graph scopes. It was proven (the
	// carteiro Gate-0 probe) to accept personal Microsoft Account sign-in with
	// no app registration, which is why it is the default. Override it with your
	// own registration for anything distributed.
	GraphCLIClientID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"

	// DefaultLoginTimeout bounds an interactive or device-code login.
	DefaultLoginTimeout = 3 * time.Minute
)

// Config configures an [Authenticator]. The zero value is usable: it defaults
// to the well-known public client, the /consumers authority, and a 3-minute
// login timeout.
type Config struct {
	// ClientID is the OAuth public client (application) id. Defaults to
	// [GraphCLIClientID].
	ClientID string

	// Authority is the OAuth2 authority URL. Defaults to [DefaultAuthority].
	Authority string

	// Scopes are the default delegated scopes requested by Login and Token when
	// no per-call scopes are given. Reserved OIDC scopes (openid, profile,
	// offline_access) are added automatically for interactive login.
	Scopes []string

	// Account is the preferred cached account (matched case-insensitively
	// against the account username) when more than one is cached. Empty means
	// "the first cached account".
	Account string

	// LoginTimeout bounds an interactive/device login. Defaults to
	// [DefaultLoginTimeout].
	LoginTimeout time.Duration
}

func (c Config) withDefaults() Config {
	if c.ClientID == "" {
		c.ClientID = GraphCLIClientID
	}
	if c.Authority == "" {
		c.Authority = DefaultAuthority
	}
	if c.LoginTimeout <= 0 {
		c.LoginTimeout = DefaultLoginTimeout
	}
	return c
}

// cacheKey partitions the token cache by client id so distinct registrations
// don't collide in a shared Store.
func (c Config) cacheKey() string {
	return "msauth:" + c.ClientID
}
