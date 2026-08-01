// Package msauth is a small, pure-Go (cgo-free) helper for Microsoft-identity
// delegated authentication, built on the Microsoft Authentication Library
// (MSAL) for Go.
//
// It exists to make CLI and desktop tools sign a user in to a personal
// Microsoft Account (or a work/school account) and obtain delegated access
// tokens, without every tool re-implementing the OAuth2 dance. It provides:
//
//   - interactive Authorization-Code + PKCE login over a robust, dual-stack
//     loopback redirect (works around MSAL Go binding only one of
//     127.0.0.1/::1, which breaks the redirect on macOS),
//   - device-code login (useful for work/school accounts; note that Microsoft
//     rejects device-code for personal accounts),
//   - silent token refresh using a persisted token cache, and
//   - a pluggable [cache.Store] with a macOS Keychain implementation and an
//     encrypted-file fallback.
//
// It is scope-agnostic: callers pass whatever delegated scopes they need
// (Microsoft Graph scopes, Outlook resource scopes, etc.). It is the shared
// auth foundation for the carteiro program (outlook-go and friends).
//
// The default client id is the well-known first-party "Microsoft Graph Command
// Line Tools" public client, which accepts personal Microsoft Accounts with no
// app registration. Override it with your own registration via [Config].
package msauth
