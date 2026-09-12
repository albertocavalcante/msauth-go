package msauth

import (
	"testing"
	"time"
)

// FuzzTokenExpiry checks the decision that governs every request: whether a
// cached token may still be used. Getting it wrong in one direction sends an
// expired bearer and fails the request; in the other it refreshes constantly
// and reinstates the cost the cache exists to avoid.
func FuzzTokenExpiry(f *testing.F) {
	f.Add(int64(3600), int64(120))
	f.Add(int64(0), int64(120))
	f.Add(int64(-1), int64(120))
	f.Add(int64(60), int64(120))
	f.Add(int64(120), int64(120))
	f.Add(int64(3600), int64(0))
	f.Add(int64(3600), int64(-5))

	now := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)

	f.Fuzz(func(t *testing.T, expiresInSeconds, skewSeconds int64) {
		// Keep both inside a range that cannot overflow a Duration.
		const limit = int64(100 * 365 * 24 * 3600)
		if expiresInSeconds < -limit || expiresInSeconds > limit ||
			skewSeconds < -limit || skewSeconds > limit {
			t.Skip()
		}

		skew := time.Duration(skewSeconds) * time.Second
		token := AccessToken{
			Value:     "v",
			ExpiresOn: now.Add(time.Duration(expiresInSeconds) * time.Second),
		}
		expired := token.Expired(now, skew)

		// A token whose life is shorter than the margin is never usable: the
		// margin exists because a request can be in flight that long.
		if expiresInSeconds <= max(skewSeconds, 0) && !expired {
			t.Fatalf("token expiring in %ds was usable with a %ds margin",
				expiresInSeconds, skewSeconds)
		}
		// One with more life than the margin always is, or the source would
		// refresh on every call.
		if expiresInSeconds > max(skewSeconds, 0) && expired {
			t.Fatalf("token expiring in %ds was rejected with a %ds margin",
				expiresInSeconds, skewSeconds)
		}
		// A negative margin must behave as none rather than extending the
		// token's life past its stated expiry.
		if skewSeconds < 0 {
			if got := token.Expired(now, 0); got != expired {
				t.Fatalf("a negative margin behaved differently from none")
			}
		}
		// A token with no stated expiry is not treated as expired: the
		// service did not say when it ends, and guessing would refresh it
		// every single call.
		noExpiry := AccessToken{Value: "v"}
		if noExpiry.Expired(now, skew) {
			t.Fatal("a token with no stated expiry was treated as expired")
		}
	})
}

// FuzzHasScope checks the membership test consent decisions are built on.
func FuzzHasScope(f *testing.F) {
	f.Add("Mail.Read", "mail.read")
	f.Add("Mail.Read", "Mail.ReadWrite")
	f.Add("", "")
	f.Add("Mail.Read", "")

	f.Fuzz(func(t *testing.T, granted, want string) {
		token := AccessToken{GrantedScopes: []string{granted}}
		got := token.HasScope(want)

		// Matching is case-insensitive because the service echoes scopes back
		// with inconsistent casing, but it is never a partial match: holding
		// Mail.ReadWrite does not mean holding Mail.Read, and treating a
		// prefix as a match would silently claim permissions not granted.
		exact := equalFoldASCII(granted, want)
		if got != exact {
			t.Fatalf("HasScope(%q) with %q granted = %v, want %v", want, granted, got, exact)
		}
	})
}
