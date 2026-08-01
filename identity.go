package msauth

// Identity describes the signed-in user, derived from the cached account and,
// after an interactive login, the id token.
type Identity struct {
	// Username is the account's preferred username (typically the email).
	Username string
	// Name is the display name from the id token. It may be empty when the
	// identity is read from the cache alone (see [Authenticator.Identity]).
	Name string
	// HomeAccountID is MSAL's stable account identifier.
	HomeAccountID string
}
