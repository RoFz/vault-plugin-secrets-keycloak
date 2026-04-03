package secretsengine

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Factory returns a new backend as logical.Backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := backend()
	if err := b.Setup(ctx, conf); err != nil {
		conf.Logger.Error("keycloak secrets engine failed to initialise", "error", err)
		return nil, err
	}
	conf.Logger.Info("keycloak secrets engine loaded successfully")
	return b, nil
}

// keycloakBackend extends the Vault backend and holds the Keycloak client.
type keycloakBackend struct {
	*framework.Backend
	lock   sync.RWMutex
	client *keycloakClient
}

// backend configures the Vault plugin backend with all paths and secrets.
func backend() *keycloakBackend {
	b := keycloakBackend{}

	b.Backend = &framework.Backend{
		Help:           strings.TrimSpace(backendHelp),
		RunningVersion: Version,
		PathsSpecial: &logical.Paths{
			LocalStorage: []string{},
			SealWrapStorage: []string{
				"config",
				"role/*",
			},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{pathConfig(&b)},
			pathRole(&b),
			pathUsers(&b),
			[]*framework.Path{pathCredentials(&b)},
		),
		Secrets:     []*framework.Secret{keycloakSecret(&b)},
		BackendType: logical.TypeLogical,
		Invalidate:  b.invalidate,
	}
	return &b
}

// reset clears the cached client so it will be re-created on next use.
func (b *keycloakBackend) reset() {
	b.lock.Lock()
	defer b.lock.Unlock()
	b.client = nil
}

// invalidate clears the client when the config changes.
func (b *keycloakBackend) invalidate(ctx context.Context, key string) {
	if key == "config" {
		b.reset()
	}
}

// getClient returns a cached Keycloak client or creates a new one from stored config.
func (b *keycloakBackend) getClient(ctx context.Context, s logical.Storage) (*keycloakClient, error) {
	b.lock.RLock()
	unlockFunc := b.lock.RUnlock
	defer func() { unlockFunc() }()

	if b.client != nil {
		return b.client, nil
	}

	b.lock.RUnlock()
	b.lock.Lock()
	unlockFunc = b.lock.Unlock

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, fmt.Errorf("configure the backend at 'config' before use")
	}

	b.client, err = newClient(config)
	if err != nil {
		b.Logger().Error("failed to create Keycloak client",
			"url", config.URL,
			"realm", config.Realm,
			"username", config.Username,
			"error", err,
		)
		return nil, err
	}

	return b.client, nil
}

const backendHelp = `
The Keycloak secrets engine rotates passwords for Keycloak realm users.

Configure the backend at "config" with the Keycloak server URL, realm name,
and a service-account client ID and secret that has the "manage-users" role.

Create roles at "role/<name>" mapping a Vault role to a Keycloak username.
Read "creds/<role>" to obtain a freshly rotated password for that user.
`
