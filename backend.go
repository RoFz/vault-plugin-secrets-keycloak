package secretsengine

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

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
	client keycloakClientIface

	// rotationLock serializes every ResetPassword + setStaticCred pair
	// (periodic, manual, and role-write initial rotations). Without it, two
	// interleaved rotations can leave storage holding a password that is no
	// longer the one set in Keycloak.
	rotationLock sync.Mutex

	// backoffMu guards rotationBackoff: per-role consecutive periodic
	// rotation failures, used to back off retries against a struggling
	// Keycloak. In-memory only: a plugin restart simply retries immediately.
	backoffMu       sync.Mutex
	rotationBackoff map[string]*rotationBackoffState
}

// rotationBackoffState tracks consecutive periodic rotation failures for one
// role and when the last attempt was made.
type rotationBackoffState struct {
	failures    int
	lastAttempt time.Time
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
				"roles/*",
				"static-creds/*",
			},
		},
		Paths: framework.PathAppend(
			[]*framework.Path{pathConfig(&b)},
			pathRole(&b),
			pathUsers(&b),
			[]*framework.Path{pathCredentials(&b)},
			[]*framework.Path{pathStaticCreds(&b)},
		),
		Secrets:      []*framework.Secret{keycloakSecret(&b)},
		BackendType:  logical.TypeLogical,
		Invalidate:   b.invalidate,
		PeriodicFunc: b.periodicFunc,
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
func (b *keycloakBackend) getClient(ctx context.Context, s logical.Storage) (keycloakClientIface, error) {
	b.lock.RLock()
	unlockFunc := b.lock.RUnlock
	defer func() { unlockFunc() }()

	if b.client != nil {
		return b.client, nil
	}

	b.lock.RUnlock()
	b.lock.Lock()
	unlockFunc = b.lock.Unlock

	// Another goroutine may have created the client between the RUnlock and
	// the Lock above.
	if b.client != nil {
		return b.client, nil
	}

	config, err := getConfig(ctx, s)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, fmt.Errorf("configure the backend at 'config' before use")
	}

	// Assign to a concrete pointer first: storing a nil *keycloakClient into
	// the interface field would make `b.client != nil` true and hand out a
	// typed-nil client (panic on first use) on every subsequent call.
	client, err := newClient(config)
	if err != nil {
		b.Logger().Error("failed to create Keycloak client",
			"url", config.URL,
			"realm", config.Realm,
			"master_admin_username", config.MasterAdminUsername,
			"error", err,
		)
		return nil, err
	}
	b.client = client

	return b.client, nil
}

const backendHelp = `
The Keycloak secrets engine rotates passwords for Keycloak realm users.

Configure the backend at "config" with the Keycloak server URL, realm name,
and a service-account client ID and secret that has the "manage-users" role.

Create roles at "roles/<name>" mapping a Vault role to a Keycloak username.
Read "creds/<role>" to obtain a freshly rotated password for that user.
`
