package msauth

import (
	"context"
	"fmt"
	"os"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"
)

// loginDevice runs the device-code flow: it prints the verification URL and
// user code, then polls until the user completes sign-in.
//
// Reminder: device-code does not work for personal Microsoft Accounts —
// Microsoft returns AADSTS90133 under /common and /consumers, and the consumers
// tenant GUID is not resolvable for discovery (AADSTS90002). Use this only for
// work/school accounts. The interactive flow is the path for personal accounts.
func (a *Authenticator) loginDevice(ctx context.Context, lc loginConfig) (public.AuthResult, error) {
	dc, err := a.client.AcquireTokenByDeviceCode(ctx, lc.scopes)
	if err != nil {
		return public.AuthResult{}, fmt.Errorf("msauth: start device code: %w", err)
	}
	if lc.prompt != nil {
		lc.prompt(dc.Result.Message)
	} else {
		fmt.Fprintln(os.Stderr, dc.Result.Message)
	}
	res, err := dc.AuthenticationResult(ctx)
	if err != nil {
		return public.AuthResult{}, fmt.Errorf("msauth: device code auth: %w", err)
	}
	return res, nil
}
