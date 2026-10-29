# msauth-go

Small, pure-Go (**cgo-free**) helper for **Microsoft-identity delegated auth**, built on [MSAL Go](https://github.com/AzureAD/microsoft-authentication-library-for-go). It signs a user into a **personal Microsoft Account** (or work/school) and hands out delegated access tokens, with a persistent token cache for silent refresh — so tools don't re-implement the OAuth2 dance.

Foundation of the **carteiro** program (→ `outlook-go`, `outlook-cli`, `carteiro`). Scope-agnostic: you pass whatever delegated scopes you need (Graph, Outlook resource, …).

## Why it exists / what's proven
- **Zero app registration by default.** Uses the well-known first-party public client *"Microsoft Graph Command Line Tools"* (`14d82eec-…`), which accepts personal accounts. Override with your own registration via `Config.ClientID`.
- **Robust interactive login.** Auth-Code + PKCE over our **own dual-stack loopback** (binds both `127.0.0.1` and `::1`). This works around MSAL Go's built-in interactive server, which binds a single stack and intermittently yields *"localhost refused to connect"* on macOS.
- **Silent refresh across restarts.** MSAL's token cache is persisted through a pluggable `cache.Store` (macOS **Keychain** or an **AES-256-GCM encrypted file**).

> Note: device-code login is included for **work/school** accounts. Microsoft rejects device-code for **personal** accounts (AADSTS90133 under `/common`/`/consumers`; the consumers tenant GUID isn't discoverable) — use the interactive flow there.

## Usage
```go
import (
    "context"
    "fmt"

    "github.com/albertocavalcante/msauth-go"
    "github.com/albertocavalcante/msauth-go/cache"
)

func main() {
    auth, err := msauth.New(msauth.Config{
        Scopes: []string{"Mail.Read"}, // defaults: Graph-CLI client, /consumers authority
    }, cache.NewKeychainStore())
    if err != nil { panic(err) }

    ctx := context.Background()

    // First run: opens the browser (one sign-in). Later runs: cache hit, no prompt.
    if _, err := auth.Identity(ctx); err != nil { // ErrLoginRequired when not cached
        id, err := auth.Login(ctx)
        if err != nil { panic(err) }
        fmt.Println("signed in as", id.Username)
    }

    token, err := auth.Token(ctx) // silently refreshed
    if err != nil { panic(err) }
    _ = token // attach as: Authorization: Bearer <token>
}
```

### Handing tokens to a REST client

`Authenticator.Token` is variadic, so it does not satisfy the
`Token(ctx) (string, error)` interface that Microsoft REST clients expect.
`TokenSource` is the scope-bound adapter that does, without either module
importing the other:

```go
graph, err := msgraph.New(auth.TokenSource("Mail.Read"))
```

It holds no token state: every call goes through the cached silent-refresh
path, so calling it per request is the intended usage. Use
`TokenInfo` instead of `Token` when the caller needs the expiry or the scopes
consent actually granted:

```go
token, err := auth.TokenInfo(ctx)
if token.Expired(time.Now(), time.Minute) { /* ... */ }
if !token.HasScope("Mail.Send") { /* consent was declined */ }
```

### Token store
- `cache.NewKeychainStore()` — macOS Keychain / Linux Secret Service (default choice).
- `cache.NewFileStore(dir)` — AES-256-GCM encrypted file (headless / no keyring). Weaker than Keychain (key sits beside data); `0700` directory and `0600` files.

### Options
- `Config`: `ClientID`, `Authority` (default `/consumers`), `Scopes`, `Account` (pick among multiple cached by username, `home_account_id`, or local account ID), `LoginTimeout`.
- `Login`: `WithDevice()`, `WithLoginScopes(...)`, `WithPrompt(fn)`, `WithBrowserOpener(fn)`.
- `Token` / `TokenInfo`: `WithScopes(...)`.

### Exact account connections

`New` and `Config.Account` retain their existing selection behavior. Tools that
manage independent connections can instead bind a client to an exact account:

```go
candidate, err := msauth.New(msauth.Config{
    Authority: "https://login.microsoftonline.com/common",
    Scopes: []string{"User.Read", "Mail.Read"},
}, candidateStore) // a separate, private Store for this candidate
if err != nil { return err }
info, err := candidate.LoginAccount(ctx)
if err != nil { return err }
// Validate info.Ref against the expected identity when reauthenticating.
bound, err := msauth.NewForAccount(msauth.Config{
    Scopes: []string{"User.Read", "Mail.Read"},
}, candidateStore, info.Ref)
if err != nil { return err }
_ = bound // publish this candidate only after identity validation succeeds
```

`AccountRef` includes the home-account ID, authority environment, resource tenant
and optional local-account ID. IDs match exactly; environment hostnames match
case-insensitively. A missing or ambiguous reference fails without using another
cached identity. `NewForAccount` pins organizational token requests to that
resource tenant and uses `/consumers` for Microsoft's documented [personal-account
tenant](https://learn.microsoft.com/en-us/entra/msal/android/accounts-overview).
Conflicting authority settings or `Config.Account` are rejected. The store layout
and legacy default authority remain unchanged.

`Accounts(ctx)` enumerates safe metadata without token acquisition or cache
writes. `Account(ctx)` returns the selected metadata. `AccountInfo.CacheRealm`
describes the cache entry's authority path: `common` and `organizations` do not
prove a tenant, so enumerating them leaves `Ref.TenantID` empty. `LoginAccount`
gets the resource tenant from the completed login result's ID-token claim;
callers never need to parse a token or raw MSAL cache. A later exact selector can
use a unique discovery entry with matching home and local IDs while explicitly
requesting the verified tenant. An exact tenant entry takes precedence once it
exists.

A bound client refuses `Login` and `LoginAccount` with `ErrBoundLogin` before
opening a browser or changing the cache. Stage reauthentication in a separate
store, verify `LoginAccount`'s result and then publish it. Like legacy `Login`,
`LoginAccount` persists the candidate before returning, including when identity
metadata validation fails; the candidate's owner must discard it on failure.

Bound `Logout` always returns `ErrAccountRemovalUnsafe` before IO. MSAL removes
all resource realms for a home identity/environment pair, and account enumeration
does not reveal every token-only record. Neither a matching discovery alias nor
the number of listed accounts proves exclusive ownership of cached credentials.
Give independently managed connections separate named keychain services or
file-store directories. The owner of such an isolated namespace may explicitly
clear it through an unbound authenticator; never apply that operation to a shared
cache as a substitute for tenant-scoped removal. Legacy `New`/`Config.Account`
logout behavior is unchanged. This library does not implement aliases, defaults,
profile lifecycle or cross-process transaction locks.

## API
`New`, `(*Authenticator).Login / Token / TokenInfo / TokenSource / Identity / Logout`. On legacy/unbound clients, `Logout` removes only `Config.Account` when set; otherwise it removes all cached accounts for the client ID. Exact-bound clients instead return `ErrAccountRemovalUnsafe` before IO. `ErrLoginRequired` is joined into errors when no usable cached account exists. `ErrNoScopes` guards the empty-scope footgun on both `Login` and `Token`. `AccessToken` carries `Value`, `ExpiresOn`, `GrantedScopes`, plus `Expired(now, skew)` and `HasScope`. Test doubles in `msauthtest` (`MemStore`).

## Develop
```sh
just ci   # fmt-check + vet + test-race + lint
```
Deps: MSAL Go, `zalando/go-keyring`, `pkg/browser`. cgo-free. `go 1.26`.

Manual live smoke test:
```sh
go run ./cmd/msauth-live-smoke
go run ./cmd/msauth-live-smoke   # second run should reuse the cache silently
```
