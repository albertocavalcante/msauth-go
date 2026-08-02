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

### Token store
- `cache.NewKeychainStore()` — macOS Keychain / Linux Secret Service (default choice).
- `cache.NewFileStore(dir)` — AES-256-GCM encrypted file (headless / no keyring). Weaker than Keychain (key sits beside data); `0700` directory and `0600` files.

### Options
- `Config`: `ClientID`, `Authority` (default `/consumers`), `Scopes`, `Account` (pick among multiple cached by username, `home_account_id`, or local account ID), `LoginTimeout`.
- `Login`: `WithDevice()`, `WithLoginScopes(...)`, `WithPrompt(fn)`, `WithBrowserOpener(fn)`.
- `Token`: `WithScopes(...)`.

## API
`New`, `(*Authenticator).Login / Token / Identity / Logout`. `Logout` removes only `Config.Account` when set; otherwise it removes all cached accounts for the client ID. `ErrLoginRequired` is joined into errors when no usable cached account exists. Test doubles in `msauthtest` (`MemStore`).

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
