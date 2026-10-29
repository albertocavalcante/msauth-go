package msauth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"

	"github.com/albertocavalcante/msauth-go/cache"
	"github.com/albertocavalcante/msauth-go/msauthtest"
)

const (
	testTenantA = "11111111-1111-1111-1111-111111111111"
	testTenantB = "22222222-2222-2222-2222-222222222222"
	testEnv     = "login.microsoftonline.com"
)

func accountFixture(home, realm, local string) public.Account {
	return public.Account{
		HomeAccountID: home, Environment: testEnv, Realm: realm,
		LocalAccountID: local, PreferredUsername: "same@example.test", Name: "Example",
	}
}

func refFixture() AccountRef {
	return AccountRef{HomeAccountID: "home-a", Environment: testEnv, TenantID: testTenantA, LocalAccountID: "local-a"}
}

func TestExactAccountSelection(t *testing.T) {
	ref := refFixture()
	wanted := accountFixture(ref.HomeAccountID, ref.TenantID, ref.LocalAccountID)
	otherTenant := accountFixture(ref.HomeAccountID, testTenantB, "local-b")
	otherHome := accountFixture("home-b", ref.TenantID, "local-b")
	cases := map[string]struct {
		accounts []public.Account
		ref      AccountRef
		want     public.Account
		err      error
	}{
		"exact among same-email accounts": {[]public.Account{otherTenant, otherHome, wanted}, ref, wanted, nil},
		"wrong tenant":                    {[]public.Account{otherTenant}, ref, public.Account{}, ErrLoginRequired},
		"missing":                         {nil, ref, public.Account{}, ErrLoginRequired},
		"duplicate exact entries":         {[]public.Account{wanted, wanted}, ref, public.Account{}, ErrAccountAmbiguous},
		"home ID remains case sensitive":  {[]public.Account{wanted}, AccountRef{"HOME-A", testEnv, testTenantA, "local-a"}, public.Account{}, ErrLoginRequired},
		"local ID remains case sensitive": {[]public.Account{wanted}, AccountRef{"home-a", testEnv, testTenantA, "LOCAL-A"},
			public.Account{}, ErrLoginRequired},
		"environment host case": {[]public.Account{wanted}, AccountRef{"home-a", strings.ToUpper(testEnv), testTenantA, "local-a"}, wanted, nil},
		"wrong environment":     {[]public.Account{wanted}, AccountRef{"home-a", "login.example.test", testTenantA, "local-a"}, public.Account{}, ErrLoginRequired},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, err := selectExactAccount(tc.accounts, tc.ref)
			if !errors.Is(err, tc.err) || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("selection = %+v, %v; want %+v, %v", got, err, tc.want, tc.err)
			}
		})
	}
}

func TestExactAccountDiscoveryFallback(t *testing.T) {
	ref := refFixture()
	discovery := accountFixture(ref.HomeAccountID, "common", ref.LocalAccountID)
	exact := discovery
	exact.Realm = testTenantA
	got, err := selectExactAccount([]public.Account{discovery}, ref)
	if err != nil || !reflect.DeepEqual(got, discovery) {
		t.Fatalf("discovery = %+v, %v", got, err)
	}
	got, err = selectExactAccount([]public.Account{discovery, exact}, ref)
	if err != nil || !reflect.DeepEqual(got, exact) {
		t.Fatalf("specific realm must win after a tenant-bound refresh: %+v, %v", got, err)
	}
	ref.LocalAccountID = ""
	if _, err := selectExactAccount([]public.Account{discovery}, ref); !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("discovery without exact local ID: %v", err)
	}
	ref.LocalAccountID = "local-a"
	organization := discovery
	organization.Realm = "organizations"
	if _, err := selectExactAccount([]public.Account{discovery, organization}, ref); !errors.Is(err, ErrAccountAmbiguous) {
		t.Fatalf("ambiguous discovery entries: %v", err)
	}
}

func TestNewForAccountAuthority(t *testing.T) {
	ref := refFixture()
	for _, configured := range []string{"", "https://" + testEnv + "/common", "https://" + testEnv + "/organizations", "https://" + testEnv + "/" + testTenantA} {
		a, err := NewForAccount(Config{Authority: configured}, msauthtest.NewMemStore(), ref)
		if err != nil {
			t.Fatalf("authority %q: %v", configured, err)
		}
		if a.cfg.Authority != "https://"+testEnv+"/"+testTenantA || a.cfg.Account != "" {
			t.Fatalf("authority not pinned: %+v", a.cfg)
		}
	}
	for _, configured := range []string{
		"https://" + testEnv + "/" + testTenantB,
		"https://" + testEnv + "/consumers",
		"https://" + testEnv + "/Consumers",
		"https://login.example.test/" + testTenantA,
		"http://" + testEnv + "/" + testTenantA,
		"https://" + testEnv + "/" + testTenantA + "?secret=fixture",
		"https://" + testEnv + "/" + testTenantA + "#fragment",
		"https://user:fixture@" + testEnv + "/" + testTenantA,
	} {
		if _, err := NewForAccount(Config{Authority: configured}, msauthtest.NewMemStore(), ref); !errors.Is(err, ErrAccountMismatch) {
			t.Fatalf("conflicting authority %q: %v", configured, err)
		} else if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "fixture") {
			t.Fatalf("authority leaked into error: %v", err)
		}
	}
	if _, err := NewForAccount(Config{Account: "same@example.test"}, msauthtest.NewMemStore(), ref); !errors.Is(err, ErrInvalidAccountRef) {
		t.Fatalf("mixed selectors: %v", err)
	}
}

func TestNewForAccountInvalidReference(t *testing.T) {
	cases := []AccountRef{
		{}, {"home", testEnv, "common", "local"}, {"home", testEnv, "organizations", "local"},
		{"home", testEnv, "consumers", "local"}, {" home", testEnv, testTenantA, "local"},
		{"home", "evil.test/path", testTenantA, "local"}, {"home", testEnv, "tenant/path", "local"},
		{"home", testEnv, testTenantA, "local\n"},
	}
	for _, ref := range cases {
		if _, err := NewForAccount(Config{}, msauthtest.NewMemStore(), ref); !errors.Is(err, ErrInvalidAccountRef) {
			t.Fatalf("ref %+v: %v", ref, err)
		}
	}
}

// Fixture cache bytes stay in tests. Production never parses the MSAL schema.
type fixtureCache struct {
	Accounts map[string]public.Account `json:"Account"`
	Tokens   map[string]fixtureToken   `json:"AccessToken"`
}

type fixtureToken struct {
	HomeAccountID string `json:"home_account_id"`
	Environment   string `json:"environment"`
	Realm         string `json:"realm"`
	ClientID      string `json:"client_id"`
	Secret        string `json:"secret"`
	Scopes        string `json:"target"`
	CachedAt      int64  `json:"cached_at"`
	ExpiresOn     int64  `json:"expires_on"`
	Extended      int64  `json:"extended_expires_on"`
}

func seededStore(t *testing.T, accounts []public.Account) *msauthtest.MemStore {
	t.Helper()
	value := fixtureCache{Accounts: make(map[string]public.Account), Tokens: make(map[string]fixtureToken)}
	for _, account := range accounts {
		key := account.HomeAccountID + "-" + account.Environment + "-" + account.Realm
		value.Accounts[key] = account
		value.Tokens[key] = fixtureToken{
			HomeAccountID: account.HomeAccountID, Environment: account.Environment, Realm: account.Realm,
			ClientID: GraphCLIClientID, Secret: "fixture-token-" + account.HomeAccountID + "@" + account.Realm, Scopes: "Mail.Read",
			CachedAt: time.Now().Add(-time.Minute).Unix(), ExpiresOn: time.Now().Add(time.Hour).Unix(),
			Extended: time.Now().Add(2 * time.Hour).Unix(),
		}
	}
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	store := msauthtest.NewMemStore()
	if err := store.Save(t.Context(), Config{}.withDefaults().cacheKey(), body); err != nil {
		t.Fatal(err)
	}
	return store
}

type rejectHTTP struct{ calls atomic.Int32 }

func (c *rejectHTTP) Do(*http.Request) (*http.Response, error) {
	c.calls.Add(1)
	return nil, errors.New("unexpected HTTP request")
}

func (*rejectHTTP) CloseIdleConnections() {}

func offlineClient(t *testing.T, a *Authenticator) *rejectHTTP {
	t.Helper()
	httpClient := &rejectHTTP{}
	client, err := public.New(a.cfg.ClientID,
		public.WithAuthority(a.cfg.Authority),
		public.WithCache(cache.NewMSALAccessor(a.store, a.key)),
		public.WithInstanceDiscovery(false), public.WithHTTPClient(httpClient))
	if err != nil {
		t.Fatal(err)
	}
	a.client = client
	return httpClient
}

func TestBoundTokenUsesSelectedTenantAndAccount(t *testing.T) {
	ref := refFixture()
	accounts := []public.Account{
		accountFixture(ref.HomeAccountID, testTenantA, ref.LocalAccountID),
		accountFixture(ref.HomeAccountID, testTenantB, "local-b"),
		accountFixture("home-b", testTenantA, "other-local"),
	}
	store := seededStore(t, accounts)
	a, err := NewForAccount(Config{Scopes: []string{"Mail.Read"}}, store, ref)
	if err != nil {
		t.Fatal(err)
	}
	httpClient := offlineClient(t, a)
	token, err := a.Token(t.Context())
	if err != nil || token != "fixture-token-"+ref.HomeAccountID+"@"+testTenantA {
		t.Fatalf("token=%q err=%v", token, err)
	}
	if httpClient.calls.Load() != 0 {
		t.Fatal("cached token made an HTTP request")
	}
}

func TestAccountEnumerationIsReadOnlyAndDistinguishesDiscovery(t *testing.T) {
	accounts := []public.Account{
		accountFixture("home-c", "consumers", "personal-local"),
		accountFixture("home-a", "common", "local-a"),
		accountFixture("home-b", testTenantA, "local-b"),
	}
	accounts[0].RawClientInfo = "fixture-secret-must-not-be-returned"
	store := seededStore(t, accounts)
	a, err := New(Config{}, store)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := store.Load(t.Context(), a.key)
	httpClient := offlineClient(t, a)
	infos, err := a.Accounts(t.Context())
	if err != nil || len(infos) != 3 {
		t.Fatalf("accounts=%+v err=%v", infos, err)
	}
	if infos[0].Ref.HomeAccountID != "home-a" || infos[0].Ref.TenantID != "" || infos[0].CacheRealm != "common" ||
		infos[2].Ref.TenantID != personalTenantID {
		t.Fatalf("metadata confused discovery with a tenant: %+v", infos)
	}
	encoded, _ := json.Marshal(infos)
	if strings.Contains(string(encoded), "fixture-secret") || strings.Contains(string(encoded), "fixture-token") {
		t.Fatal("account metadata exposed token or raw client info")
	}
	after, _ := store.Load(t.Context(), a.key)
	if string(before) != string(after) || httpClient.calls.Load() != 0 {
		t.Fatal("enumeration changed cache or requested network")
	}
}

func TestBoundLogoutRefusesUnsupportedRemovalWithoutMutation(t *testing.T) {
	ref := refFixture()
	store := seededStore(t, []public.Account{
		accountFixture(ref.HomeAccountID, ref.TenantID, ref.LocalAccountID),
		accountFixture("other-home", testTenantB, "other-local"),
	})
	a, err := NewForAccount(Config{}, store, ref)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := store.Load(t.Context(), a.key)
	if err := a.Logout(t.Context()); !errors.Is(err, ErrAccountRemovalUnsafe) {
		t.Fatalf("bound removal: %v", err)
	}
	after, _ := store.Load(t.Context(), a.key)
	if string(before) != string(after) {
		t.Fatal("refused removal changed cached data")
	}
	infos, err := a.Accounts(t.Context())
	if err != nil || len(infos) != 2 {
		t.Fatalf("accounts changed: %+v %v", infos, err)
	}
}

func TestBoundLogoutRefusesMSALCrossTenantRemoval(t *testing.T) {
	ref := refFixture()
	store := seededStore(t, []public.Account{
		accountFixture(ref.HomeAccountID, ref.TenantID, ref.LocalAccountID),
		accountFixture(ref.HomeAccountID, testTenantB, "local-b"),
	})
	a, err := NewForAccount(Config{}, store, ref)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := store.Load(t.Context(), a.key)
	if err := a.Logout(t.Context()); !errors.Is(err, ErrAccountRemovalUnsafe) {
		t.Fatalf("unsafe logout err=%v", err)
	}
	after, _ := store.Load(t.Context(), a.key)
	if string(before) != string(after) {
		t.Fatal("refused logout changed store")
	}
}

func TestBoundLogoutRefusesUnverifiedDiscoveryOwnership(t *testing.T) {
	ref := refFixture()
	store := seededStore(t, []public.Account{
		accountFixture(ref.HomeAccountID, "common", ref.LocalAccountID),
		accountFixture(ref.HomeAccountID, ref.TenantID, ref.LocalAccountID),
	})
	a, err := NewForAccount(Config{}, store, ref)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := store.Load(t.Context(), a.key)
	if err := a.Logout(t.Context()); !errors.Is(err, ErrAccountRemovalUnsafe) {
		t.Fatalf("discovery ownership inferred: %v", err)
	}
	after, _ := store.Load(t.Context(), a.key)
	if string(before) != string(after) {
		t.Fatal("refused removal changed cached data")
	}
}

func TestBoundLoginRefusedBeforeBrowserOrStoreChange(t *testing.T) {
	ref := refFixture()
	store := seededStore(t, []public.Account{accountFixture(ref.HomeAccountID, ref.TenantID, ref.LocalAccountID)})
	a, err := NewForAccount(Config{Scopes: []string{"Mail.Read"}}, store, ref)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := store.Load(t.Context(), a.key)
	opened := false
	option := WithBrowserOpener(func(string) error { opened = true; return nil })
	if _, err := a.LoginAccount(t.Context(), option); !errors.Is(err, ErrBoundLogin) {
		t.Fatalf("LoginAccount err=%v", err)
	}
	if _, err := a.Login(t.Context(), option); !errors.Is(err, ErrBoundLogin) {
		t.Fatalf("Login err=%v", err)
	}
	after, _ := store.Load(t.Context(), a.key)
	if opened || string(before) != string(after) {
		t.Fatal("bound login opened browser or changed cache")
	}
}

func TestLoginAccountInfoUsesTenantClaim(t *testing.T) {
	res := public.AuthResult{Account: accountFixture("home", "common", "local")}
	res.IDToken.TenantID = testTenantB
	res.IDToken.Name = "Signed in person"
	info, err := loginAccountInfo(res)
	if err != nil || info.Ref.TenantID != testTenantB || info.CacheRealm != "common" || info.Name != res.IDToken.Name {
		t.Fatalf("login metadata=%+v err=%v", info, err)
	}
	res.Account.Realm = testTenantA
	if _, err := loginAccountInfo(res); !errors.Is(err, ErrAccountMismatch) {
		t.Fatalf("conflicting claim=%v", err)
	}
	res.Account.Realm = "common"
	res.IDToken.TenantID = ""
	if _, err := loginAccountInfo(res); !errors.Is(err, ErrAccountMismatch) {
		t.Fatalf("missing claim=%v", err)
	}
}

func TestPersonalAccountBindingRetainsConsumersAuthority(t *testing.T) {
	ref := AccountRef{"personal-home", testEnv, personalTenantID, "personal-local"}
	store := seededStore(t, []public.Account{accountFixture(ref.HomeAccountID, "consumers", ref.LocalAccountID)})
	a, err := NewForAccount(Config{Scopes: []string{"Mail.Read"}}, store, ref)
	if err != nil {
		t.Fatal(err)
	}
	if parsed, _ := url.Parse(a.cfg.Authority); parsed.Path != "/consumers" {
		t.Fatalf("personal authority=%q", a.cfg.Authority)
	}
	httpClient := offlineClient(t, a)
	token, err := a.Token(t.Context())
	if err != nil || token != "fixture-token-"+ref.HomeAccountID+"@consumers" || httpClient.calls.Load() != 0 {
		t.Fatalf("personal cached token=%q err=%v calls=%d", token, err, httpClient.calls.Load())
	}
	if _, err := NewForAccount(Config{Authority: "https://" + testEnv + "/organizations"}, store, ref); !errors.Is(err, ErrAccountMismatch) {
		t.Fatalf("organizational-only authority accepted personal context: %v", err)
	}
	if _, err := NewForAccount(Config{Authority: "https://" + testEnv + "/Organizations"}, store, ref); !errors.Is(err, ErrAccountMismatch) {
		t.Fatalf("mixed-case organizational authority accepted personal context: %v", err)
	}
}

func TestTwoPersonalAccountsUseExactHomeIdentity(t *testing.T) {
	ref := AccountRef{"personal-b", testEnv, personalTenantID, "local-b"}
	store := seededStore(t, []public.Account{
		accountFixture("personal-a", "consumers", "local-a"),
		accountFixture(ref.HomeAccountID, "consumers", ref.LocalAccountID),
	})
	a, err := NewForAccount(Config{Scopes: []string{"Mail.Read"}}, store, ref)
	if err != nil {
		t.Fatal(err)
	}
	httpClient := offlineClient(t, a)
	token, err := a.Token(t.Context())
	if err != nil || token != "fixture-token-personal-b@consumers" || httpClient.calls.Load() != 0 {
		t.Fatalf("selected personal token=%q err=%v", token, err)
	}
}

func TestMissingBoundAccountDoesNotAcquireAnotherToken(t *testing.T) {
	store := seededStore(t, []public.Account{accountFixture("other-home", testTenantA, "other-local")})
	a, err := NewForAccount(Config{Scopes: []string{"Mail.Read"}}, store, refFixture())
	if err != nil {
		t.Fatal(err)
	}
	httpClient := offlineClient(t, a)
	if token, err := a.Token(t.Context()); token != "" || !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("missing selector fell back: token=%q err=%v", token, err)
	}
	if httpClient.calls.Load() != 0 {
		t.Fatal("missing exact identity attempted acquisition")
	}
}

func TestBoundLogoutPreservesUnreadableStore(t *testing.T) {
	store := msauthtest.NewMemStore()
	key := Config{}.withDefaults().cacheKey()
	before := []byte("not valid cache JSON")
	if err := store.Save(t.Context(), key, before); err != nil {
		t.Fatal(err)
	}
	a, err := NewForAccount(Config{}, store, refFixture())
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Logout(t.Context()); err == nil {
		t.Fatal("unreadable store was silently deleted")
	}
	after, _ := store.Load(t.Context(), key)
	if string(before) != string(after) {
		t.Fatal("failed account enumeration changed store")
	}
}

func TestBoundTokenResultMetadata(t *testing.T) {
	ref := refFixture()
	a := &Authenticator{bound: &ref}
	result := public.AuthResult{Account: accountFixture(ref.HomeAccountID, ref.TenantID, ref.LocalAccountID)}
	if err := a.checkTokenAccount(result); err != nil {
		t.Fatal(err)
	}
	result.Account.Realm = testTenantB
	if err := a.checkTokenAccount(result); !errors.Is(err, ErrAccountMismatch) {
		t.Fatalf("wrong returned realm: %v", err)
	}
	result.Account = accountFixture("other-home", ref.TenantID, ref.LocalAccountID)
	if err := a.checkTokenAccount(result); !errors.Is(err, ErrAccountMismatch) {
		t.Fatalf("wrong returned identity: %v", err)
	}
	result.Account = public.Account{}
	if err := a.checkTokenAccount(result); err != nil {
		t.Fatalf("refresh without identity metadata must use bound request context: %v", err)
	}
	result.IDToken.TenantID = testTenantB
	if err := a.checkTokenAccount(result); !errors.Is(err, ErrAccountMismatch) {
		t.Fatalf("wrong returned ID-token tenant: %v", err)
	}
}

type loginFixtureClient struct {
	public.Client
	result public.AuthResult
	code   string
}

func (c *loginFixtureClient) AcquireTokenByAuthCode(_ context.Context, code, _ string, _ []string, _ ...public.AcquireByAuthCodeOption) (public.AuthResult, error) {
	c.code = code
	return c.result, nil
}

func TestLoginAccountReturnsFullContextThroughBrowserFlow(t *testing.T) {
	a, err := New(Config{Scopes: []string{"Mail.Read"}, LoginTimeout: 5 * time.Second}, msauthtest.NewMemStore())
	if err != nil {
		t.Fatal(err)
	}
	result := public.AuthResult{Account: accountFixture("home", "common", "local")}
	result.IDToken.TenantID = testTenantB
	result.IDToken.Name = "Example person"
	backend := &loginFixtureClient{result: result}
	a.client = backend
	info, err := a.LoginAccount(t.Context(), WithBrowserOpener(func(raw string) error {
		authorize, parseErr := url.Parse(raw)
		if parseErr != nil {
			return parseErr
		}
		callback, parseErr := url.Parse(authorize.Query().Get("redirect_uri"))
		if parseErr != nil {
			return parseErr
		}
		callback.RawQuery = url.Values{"state": {authorize.Query().Get("state")}, "code": {"fixture-code"}}.Encode()
		request, requestErr := http.NewRequestWithContext(t.Context(), http.MethodGet, callback.String(), nil)
		if requestErr != nil {
			return requestErr
		}
		response, requestErr := http.DefaultClient.Do(request)
		if requestErr != nil {
			return requestErr
		}
		return response.Body.Close()
	}))
	if err != nil {
		t.Fatal(err)
	}
	if backend.code != "fixture-code" || info.Ref.HomeAccountID != "home" || info.Ref.TenantID != testTenantB ||
		info.CacheRealm != "common" || info.Name != result.IDToken.Name {
		t.Fatalf("login result=%+v backend code=%q", info, backend.code)
	}
}

func TestLegacySelectionStillAcceptsCaseInsensitiveIDs(t *testing.T) {
	account := accountFixture("Home-A", testTenantA, "Local-A")
	store := seededStore(t, []public.Account{account})
	a, err := New(Config{Account: "home-a"}, store)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := a.Identity(t.Context())
	if err != nil || identity.HomeAccountID != "Home-A" {
		t.Fatalf("legacy identity=%+v err=%v", identity, err)
	}
}
