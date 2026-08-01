// Command msauth-live-smoke verifies interactive login plus silent token reuse.
//
// It is intentionally a manual live check. It never prints access tokens.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	msauth "github.com/albertocavalcante/msauth-go"
	"github.com/albertocavalcante/msauth-go/cache"
)

func main() {
	scopesFlag := flag.String("scopes", "Mail.Read", "comma-separated delegated scopes")
	device := flag.Bool("device", false, "use device-code login when a login is required")
	flag.Parse()

	scopes := splitScopes(*scopesFlag)
	if len(scopes) == 0 {
		fmt.Fprintln(os.Stderr, "at least one scope is required")
		os.Exit(2)
	}

	auth, err := msauth.New(msauth.Config{Scopes: scopes}, cache.NewKeychainStore())
	if err != nil {
		fmt.Fprintf(os.Stderr, "new authenticator: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	id, err := auth.Identity(ctx)
	if errors.Is(err, msauth.ErrLoginRequired) {
		opts := []msauth.LoginOption{}
		if *device {
			opts = append(opts, msauth.WithDevice())
		}
		id, err = auth.Login(ctx, opts...)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "identity/login: %v\n", err)
		os.Exit(1)
	}

	if _, err := auth.Token(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "token: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("token_ok=true username=%q home_account_id=%q\n", id.Username, id.HomeAccountID)
}

func splitScopes(value string) []string {
	var scopes []string
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			scopes = append(scopes, part)
		}
	}
	return scopes
}
