package secretsengine

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// staticCredEntry holds the autorotated password for a static (non-ephemeral) role.
type staticCredEntry struct {
	Password     string    `json:"password"`
	LastRotation time.Time `json:"last_rotation"`
}

// getStaticCred loads the stored credential for a static role. Returns nil if none exists yet.
func getStaticCred(ctx context.Context, s logical.Storage, roleName string) (*staticCredEntry, error) {
	entry, err := s.Get(ctx, "static-creds/"+roleName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var cred staticCredEntry
	if err := entry.DecodeJSON(&cred); err != nil {
		return nil, fmt.Errorf("error decoding static credential: %w", err)
	}
	return &cred, nil
}

// setStaticCred persists a static credential entry.
func setStaticCred(ctx context.Context, s logical.Storage, roleName string, cred *staticCredEntry) error {
	entry, err := logical.StorageEntryJSON("static-creds/"+roleName, cred)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

// rotateStaticCred generates a new password, sets it in Keycloak, stores the
// staticCredEntry, and optionally syncs to KV v2.
func (b *keycloakBackend) rotateStaticCred(ctx context.Context, s logical.Storage, roleName string, role *keycloakRoleEntry) error {
	client, err := b.getClient(ctx, s)
	if err != nil {
		return err
	}

	password, err := generatePassword()
	if err != nil {
		return fmt.Errorf("error generating password: %w", err)
	}

	if err := client.ResetPassword(ctx, role.KeycloakUsername, password); err != nil {
		return fmt.Errorf("error rotating password for user %q: %w", role.KeycloakUsername, err)
	}

	cred := &staticCredEntry{
		Password:     password,
		LastRotation: time.Now(),
	}
	if err := setStaticCred(ctx, s, roleName, cred); err != nil {
		return fmt.Errorf("error storing static credential: %w", err)
	}

	b.Logger().Info("static credential rotated",
		"role", roleName,
		"keycloak_username", role.KeycloakUsername,
	)

	if role.KVPasswordKey != "" {
		config, err := getConfig(ctx, s)
		if err == nil && config != nil && config.KVMountPath != "" && config.KVSecretPath != "" {
			vaultAddr := config.KVAPIAddr
			if vaultAddr == "" {
				vaultAddr = "https://127.0.0.1:8200"
			}
			if config.KVToken == "" {
				b.Logger().Warn("kv sync skipped: kv_token not configured", "role", roleName)
			} else if _, err := writeKVSecret(ctx, vaultAddr, config.KVToken, config.KVMountPath, config.KVSecretPath, role.KVPasswordKey, password, config.KVTLSSkipVerify); err != nil {
				b.Logger().Error("kv sync failed after static rotation",
					"role", roleName,
					"keycloak_username", role.KeycloakUsername,
					"error", err,
				)
			}
		}
	}

	return nil
}

// periodicFunc is called by Vault approximately every minute. It rotates any
// static role whose rotation_period has elapsed since the last rotation.
func (b *keycloakBackend) periodicFunc(ctx context.Context, req *logical.Request) error {
	roles, err := req.Storage.List(ctx, "roles/")
	if err != nil {
		return fmt.Errorf("periodic: failed to list roles: %w", err)
	}

	for _, roleName := range roles {
		role, err := b.getRole(ctx, req.Storage, roleName)
		if err != nil {
			b.Logger().Error("periodic: failed to load role", "role", roleName, "error", err)
			continue
		}
		if role == nil || role.Ephemeral {
			continue
		}
		// Defense in depth: a static role must have a positive rotation_period
		// (the getRole compat shim classifies rotation_period==0 as ephemeral).
		// Never rotate on a zero/negative period: with the time.Since check
		// below it would rotate the user's password on every periodic tick.
		if role.RotationPeriod <= 0 {
			b.Logger().Error("periodic: static role has no rotation_period; skipping",
				"role", roleName,
			)
			continue
		}

		cred, err := getStaticCred(ctx, req.Storage, roleName)
		if err != nil {
			b.Logger().Error("periodic: failed to load static cred", "role", roleName, "error", err)
			continue
		}

		needsRotation := cred == nil || time.Since(cred.LastRotation) >= role.RotationPeriod
		if !needsRotation {
			continue
		}

		if err := b.rotateStaticCred(ctx, req.Storage, roleName, role); err != nil {
			b.Logger().Error("periodic: rotation failed", "role", roleName, "error", err)
		}
	}

	return nil
}

// syncStaticCredsForUsername updates the stored staticCredEntry for every
// non-ephemeral role that maps to the given Keycloak username. Called after a
// manual rotation so the autorotation timer is reset to now.
func (b *keycloakBackend) syncStaticCredsForUsername(ctx context.Context, s logical.Storage, username, password string) error {
	roleNames, err := s.List(ctx, "roles/")
	if err != nil {
		return fmt.Errorf("failed to list roles: %w", err)
	}

	for _, roleName := range roleNames {
		role, err := b.getRole(ctx, s, roleName)
		if err != nil || role == nil {
			continue
		}
		if role.Ephemeral || role.KeycloakUsername != username {
			continue
		}

		cred := &staticCredEntry{
			Password:     password,
			LastRotation: time.Now(),
		}
		if err := setStaticCred(ctx, s, roleName, cred); err != nil {
			b.Logger().Error("failed to update static cred after manual rotation",
				"role", roleName,
				"keycloak_username", username,
				"error", err,
			)
			continue
		}
		b.Logger().Info("static cred timer reset after manual rotation",
			"role", roleName,
			"keycloak_username", username,
		)

		if role.KVPasswordKey != "" {
			config, err := getConfig(ctx, s)
			if err == nil && config != nil && config.KVMountPath != "" && config.KVSecretPath != "" {
				vaultAddr := config.KVAPIAddr
				if vaultAddr == "" {
					vaultAddr = "https://127.0.0.1:8200"
				}
				if config.KVToken != "" {
					if _, err := writeKVSecret(ctx, vaultAddr, config.KVToken, config.KVMountPath, config.KVSecretPath, role.KVPasswordKey, password, config.KVTLSSkipVerify); err != nil {
						b.Logger().Error("kv sync failed after manual rotation",
							"role", roleName,
							"error", err,
						)
					}
				}
			}
		}
	}

	return nil
}

// pathStaticCreds registers the static-creds/<name> read endpoint.
func pathStaticCreds(b *keycloakBackend) *framework.Path {
	return &framework.Path{
		Pattern: "static-creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the static role to read credentials for.",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathStaticCredsRead,
				Summary:  "Read the current password for a static (autorotated) Keycloak role.",
			},
		},
		HelpSynopsis:    pathStaticCredsHelpSyn,
		HelpDescription: pathStaticCredsHelpDesc,
	}
}

func (b *keycloakBackend) pathStaticCredsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role %q not found", roleName), nil
	}
	if role.Ephemeral {
		return logical.ErrorResponse("role %q is ephemeral; use creds/%s", roleName, roleName), nil
	}

	cred, err := getStaticCred(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if cred == nil {
		return logical.ErrorResponse("no credential available for role %q; rotation pending", roleName), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"username":        role.KeycloakUsername,
			"password":        cred.Password,
			"last_rotation":   cred.LastRotation.Format(time.RFC3339),
			"rotation_period": role.RotationPeriod.Seconds(),
		},
	}, nil
}

const pathStaticCredsHelpSyn = `Read the current autorotated password for a static Keycloak role.`

const pathStaticCredsHelpDesc = `
Returns the most recently rotated password for the Keycloak user bound to
this static role. No lease is created — the same password is returned on
every read until the next autorotation.

Use creds/<name> for ephemeral lease-bound credentials instead.
`
