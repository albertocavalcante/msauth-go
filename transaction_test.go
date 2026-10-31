package msauth

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/public"

	"github.com/albertocavalcante/msauth-go/cache"
)

type transactionClient struct {
	store  cache.Store
	key    string
	owner  string
	loaded func(context.Context) error
}

func (c *transactionClient) Accounts(context.Context) ([]public.Account, error) {
	return []public.Account{{PreferredUsername: c.owner, HomeAccountID: c.owner}}, nil
}
func (*transactionClient) RemoveAccount(context.Context, public.Account) error {
	return errors.New("not used")
}
func (*transactionClient) AcquireTokenByAuthCode(context.Context, string, string, []string, ...public.AcquireByAuthCodeOption) (public.AuthResult, error) {
	return public.AuthResult{}, errors.New("not used")
}
func (*transactionClient) AcquireTokenByDeviceCode(context.Context, []string, ...public.AcquireByDeviceCodeOption) (public.DeviceCode, error) {
	return public.DeviceCode{}, errors.New("not used")
}
func (c *transactionClient) AcquireTokenSilent(ctx context.Context, _ []string, _ ...public.AcquireSilentOption) (public.AuthResult, error) {
	b, err := c.store.Load(ctx, c.key)
	if err != nil {
		return public.AuthResult{}, err
	}
	values := map[string]int{}
	if err := json.Unmarshal(b, &values); err != nil {
		return public.AuthResult{}, err
	}
	if c.loaded != nil {
		if err := c.loaded(ctx); err != nil {
			return public.AuthResult{}, err
		}
	}
	values[c.owner]++
	b, err = json.Marshal(values)
	if err != nil {
		return public.AuthResult{}, err
	}
	if err := c.store.Save(ctx, c.key, b); err != nil {
		return public.AuthResult{}, err
	}
	return public.AuthResult{AccessToken: "synthetic", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func TestTokenInfoCoordinatesSharedCache(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	store := cache.NewFileStore(t.TempDir())
	const key = "shared-client"
	if err := store.Save(ctx, key, []byte("{}")); err != nil {
		t.Fatal(err)
	}
	firstRead := make(chan struct{})
	secondRead := make(chan struct{})
	release := make(chan struct{})
	first := &transactionClient{store: store, key: key, owner: "first", loaded: func(ctx context.Context) error {
		close(firstRead)
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}}
	second := &transactionClient{store: store, key: key, owner: "second", loaded: func(context.Context) error {
		close(secondRead)
		return nil
	}}
	call := func(client publicClient) error {
		a := &Authenticator{cfg: Config{Scopes: []string{"Mail.Read"}}, store: store, key: key, client: client}
		_, err := a.TokenInfo(ctx)
		return err
	}
	results := make(chan error, 2)
	go func() { results <- call(first) }()
	select {
	case <-firstRead:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	go func() { results <- call(second) }()
	overlap := false
	select {
	case <-secondRead:
		overlap = true
	case <-time.After(150 * time.Millisecond):
	}
	close(release)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatal(err)
		}
	}
	blob, err := store.Load(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	var values map[string]int
	if err := json.Unmarshal(blob, &values); err != nil {
		t.Fatal(err)
	}
	if overlap || values["first"] != 1 || values["second"] != 1 {
		t.Fatalf("cache operations overlapped or lost an update: overlap=%v values=%v", overlap, values)
	}
}

func TestTransactionalMetadataDoesNotResurrectDeletedAccount(t *testing.T) {
	ctx := t.Context()
	seed := seededStore(t, []public.Account{accountFixture("home", testTenantA, "local")})
	key := Config{}.withDefaults().cacheKey()
	blob, err := seed.Load(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	store := cache.NewFileStore(t.TempDir())
	if err := store.Save(ctx, key, blob); err != nil {
		t.Fatal(err)
	}
	a, err := New(Config{Account: "same@example.test"}, store)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.Identity(ctx); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(ctx, key); err != nil {
		t.Fatal(err)
	}
	if _, err := a.Identity(ctx); !errors.Is(err, ErrLoginRequired) {
		t.Fatalf("deleted credentials survived in-memory cache: %v", err)
	}
}
