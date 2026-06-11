package secretsengine

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// keycloakRoleEntry maps a Vault role name to a Keycloak username.
type keycloakRoleEntry struct {
	KeycloakUsername string        `json:"keycloak_username"`
	Ephemeral        bool          `json:"ephemeral"`
	TTL              time.Duration `json:"ttl"`
	MaxTTL           time.Duration `json:"max_ttl"`
	RotationPeriod   time.Duration `json:"rotation_period"`
	KVPasswordKey    string        `json:"kv_password_key"`
}

// toResponseData returns the role fields safe to show in a read response.
func (r *keycloakRoleEntry) toResponseData() map[string]interface{} {
	return map[string]interface{}{
		"keycloak_username": r.KeycloakUsername,
		"ephemeral":         r.Ephemeral,
		"ttl":               r.TTL.Seconds(),
		"max_ttl":           r.MaxTTL.Seconds(),
		"rotation_period":   r.RotationPeriod.Seconds(),
		"kv_password_key":   r.KVPasswordKey,
	}
}

// pathRole registers the /roles/<name> and /roles/ (list) endpoints.
func pathRole(b *keycloakBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeLowerCaseString,
					Description: "Name of the Vault role.",
					Required:    true,
				},
				"keycloak_username": {
					Type:        framework.TypeString,
					Description: "Keycloak username whose password will be rotated when credentials are requested.",
					Required:    true,
				},
				"ephemeral": {
					Type:        framework.TypeBool,
					Description: "If true, the role issues lease-bound ephemeral credentials via creds/<name>. If false (default), the role uses background autorotation and credentials are read from static-creds/<name>.",
					Default:     false,
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Lease duration for ephemeral roles. Required when ephemeral=true; minimum 1 minute.",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum lease duration for ephemeral roles. Required when ephemeral=true; must be >= ttl.",
				},
				"rotation_period": {
					Type:        framework.TypeDurationSecond,
					Description: "How often to autorotate the password for static roles. Required when ephemeral=false; minimum 30 minutes.",
				},
				"kv_password_key": {
					Type:        framework.TypeString,
					Description: "KV v2 key to PATCH with the new password after rotation. Optional.",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRoleRead,
					Summary:  "Read a Keycloak role definition.",
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRoleWrite,
					Summary:  "Create a Keycloak role definition.",
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRoleWrite,
					Summary:  "Update a Keycloak role definition.",
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRoleDelete,
					Summary:  "Delete a Keycloak role definition.",
				},
			},
			ExistenceCheck:  b.pathRoleExistenceCheck,
			HelpSynopsis:    pathRoleHelpSynopsis,
			HelpDescription: pathRoleHelpDescription,
		},
		{
			Pattern: "roles/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRoleList,
					Summary:  "List all Keycloak role definitions.",
				},
			},
			HelpSynopsis:    pathRoleListHelpSynopsis,
			HelpDescription: pathRoleListHelpDescription,
		},
	}
}

func (b *keycloakBackend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	role, err := b.getRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return role != nil, nil
}

func (b *keycloakBackend) pathRoleRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	role, err := b.getRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}
	return &logical.Response{Data: role.toResponseData()}, nil
}

func (b *keycloakBackend) pathRoleWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	prior, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	role := &keycloakRoleEntry{}
	if prior != nil {
		*role = *prior
	}

	if v, ok := data.GetOk("keycloak_username"); ok {
		role.KeycloakUsername = v.(string)
	}
	if role.KeycloakUsername == "" {
		return logical.ErrorResponse("keycloak_username is required"), nil
	}

	if v, ok := data.GetOk("ephemeral"); ok {
		role.Ephemeral = v.(bool)
	}

	if role.Ephemeral {
		// Ephemeral mode: ttl and max_ttl required, rotation_period rejected.
		if v, ok := data.GetOk("rotation_period"); ok && v.(int) != 0 {
			return logical.ErrorResponse("rotation_period is not allowed for ephemeral roles; use ttl and max_ttl instead"), nil
		}
		if v, ok := data.GetOk("ttl"); ok {
			role.TTL = time.Duration(v.(int)) * time.Second
		}
		if role.TTL < 60*time.Second {
			return logical.ErrorResponse("ttl is required for ephemeral roles and must be at least 1 minute (60s)"), nil
		}
		if v, ok := data.GetOk("max_ttl"); ok {
			role.MaxTTL = time.Duration(v.(int)) * time.Second
		}
		if role.MaxTTL == 0 {
			return logical.ErrorResponse("max_ttl is required for ephemeral roles"), nil
		}
		if role.MaxTTL < role.TTL {
			return logical.ErrorResponse("max_ttl must be greater than or equal to ttl"), nil
		}
		// Ephemeral roles never autorotate; drop any rotation_period left over
		// from a previous static phase.
		role.RotationPeriod = 0
	} else {
		// Static (non-ephemeral) mode: rotation_period required, ttl/max_ttl rejected.
		if v, ok := data.GetOk("ttl"); ok && v.(int) != 0 {
			return logical.ErrorResponse("ttl is not allowed for static roles; use rotation_period instead"), nil
		}
		if v, ok := data.GetOk("max_ttl"); ok && v.(int) != 0 {
			return logical.ErrorResponse("max_ttl is not allowed for static roles; use rotation_period instead"), nil
		}
		if v, ok := data.GetOk("rotation_period"); ok {
			role.RotationPeriod = time.Duration(v.(int)) * time.Second
		}
		if role.RotationPeriod < 30*time.Minute {
			return logical.ErrorResponse("rotation_period is required for static roles and must be at least 30 minutes (1800s)"), nil
		}
		// Static roles have no lease; drop any ttl/max_ttl left over from a
		// previous ephemeral phase.
		role.TTL = 0
		role.MaxTTL = 0
	}

	if v, ok := data.GetOk("kv_password_key"); ok {
		role.KVPasswordKey = v.(string)
	}

	// A Keycloak user may be shared by multiple ephemeral roles (pre-v0.3.0
	// behaviour), but never by a static role and anything else: concurrent
	// rotation paths would silently invalidate each other's passwords.
	if resp, err := b.checkUsernameExclusive(ctx, req.Storage, name, role); err != nil || resp != nil {
		return resp, err
	}

	// Converting static -> ephemeral stops managing the credential: drop the
	// stored entry (static-creds/<name> no longer serves this role). The live
	// Keycloak password is intentionally left working, so consumers survive
	// the conversion (continuity-first design). To revoke it instead, call
	// users/<username>/rotate before converting.
	if prior != nil && !prior.Ephemeral && role.Ephemeral {
		if err := req.Storage.Delete(ctx, "static-creds/"+name); err != nil {
			return nil, err
		}
	}

	// A static role needs an immediate rotation when it is new (or retrying a
	// previously failed first rotation), repointed at a different Keycloak
	// user (the stored credential belongs to the old user), or converted from
	// ephemeral mode (any stored credential predates the conversion).
	needsRotation := false
	if !role.Ephemeral {
		existingCred, err := getStaticCred(ctx, req.Storage, name)
		if err != nil {
			return nil, err
		}
		usernameChanged := prior != nil && prior.KeycloakUsername != role.KeycloakUsername
		convertedToStatic := prior != nil && prior.Ephemeral
		needsRotation = existingCred == nil || usernameChanged || convertedToStatic
	}

	// Rotate BEFORE persisting: a failed rotation must leave any prior role
	// definition untouched instead of deleting it.
	if needsRotation {
		if rotErr := b.rotateStaticCred(ctx, req.Storage, name, role); rotErr != nil {
			return nil, fmt.Errorf("initial rotation failed: %w", rotErr)
		}
	}

	if err := b.setRole(ctx, req.Storage, name, role); err != nil {
		if needsRotation {
			// Best effort: drop the just-written credential so storage cannot
			// pair the prior role definition with the new user's password.
			// periodicFunc re-rotates from the persisted role on the next tick.
			_ = req.Storage.Delete(ctx, "static-creds/"+name)
		}
		return nil, err
	}

	return nil, nil
}

// checkUsernameExclusive returns an error response when the candidate role's
// keycloak_username is already mapped by another role in a conflicting mode.
// Sharing is allowed only between ephemeral roles.
func (b *keycloakBackend) checkUsernameExclusive(ctx context.Context, s logical.Storage, name string, role *keycloakRoleEntry) (*logical.Response, error) {
	roleNames, err := s.List(ctx, "roles/")
	if err != nil {
		return nil, fmt.Errorf("error listing roles: %w", err)
	}
	for _, other := range roleNames {
		if other == name {
			continue
		}
		otherRole, err := b.getRole(ctx, s, other)
		if err != nil {
			return nil, err
		}
		if otherRole == nil || otherRole.KeycloakUsername != role.KeycloakUsername {
			continue
		}
		if role.Ephemeral && otherRole.Ephemeral {
			continue
		}
		return logical.ErrorResponse(
			"keycloak_username %q is already mapped by role %q; a username may be shared only between ephemeral roles",
			role.KeycloakUsername, other,
		), nil
	}
	return nil, nil
}

// discardPassword rotates the user's Keycloak password to a random value that
// is never stored or returned, invalidating whatever credential was live.
// Used only by lease revocation: invalidation-on-revoke is the defining
// semantic of a lease. Role delete and mode conversion intentionally leave
// the live password working (continuity-first design).
func (b *keycloakBackend) discardPassword(ctx context.Context, s logical.Storage, username string) error {
	b.rotationLock.Lock()
	defer b.rotationLock.Unlock()

	client, err := b.getClient(ctx, s)
	if err != nil {
		return err
	}
	discarded, err := generatePassword()
	if err != nil {
		return fmt.Errorf("error generating discard password: %w", err)
	}
	if err := client.ResetPassword(ctx, username, discarded); err != nil {
		return err
	}
	b.Logger().Info("managed password discarded",
		"keycloak_username", username,
	)
	return nil
}

func (b *keycloakBackend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)

	// Deleting a role removes Vault's state only. The last password set in
	// Keycloak intentionally stays working so consumers survive the deletion
	// and a Vault decommission never strands services (continuity-first
	// design). To revoke the credential instead, rotate it first:
	// users/<username>/rotate, then delete the role.
	if err := req.Storage.Delete(ctx, "roles/"+name); err != nil {
		return nil, err
	}
	if err := req.Storage.Delete(ctx, "static-creds/"+name); err != nil {
		return nil, err
	}
	b.clearRotationBackoff(name)
	return nil, nil
}

func (b *keycloakBackend) pathRoleList(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, "roles/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(entries), nil
}

func (b *keycloakBackend) getRole(ctx context.Context, s logical.Storage, name string) (*keycloakRoleEntry, error) {
	entry, err := s.Get(ctx, "roles/"+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var role keycloakRoleEntry
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, fmt.Errorf("error decoding role: %w", err)
	}

	// Backward compat: every role written by v0.1.x/v0.2.x is lease-bound and
	// has no rotation_period (ttl/max_ttl may be zero too: GetOk never stores
	// schema defaults, so roles created without an explicit ttl carry TTL=0).
	// A missing rotation_period therefore always means ephemeral, so legacy
	// roles keep working with creds/<role> and are never autorotated.
	if !role.Ephemeral && role.RotationPeriod == 0 {
		role.Ephemeral = true
	}

	return &role, nil
}

func (b *keycloakBackend) setRole(ctx context.Context, s logical.Storage, name string, role *keycloakRoleEntry) error {
	entry, err := logical.StorageEntryJSON("roles/"+name, role)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

const (
	pathRoleHelpSynopsis    = `Manage Vault roles for Keycloak password rotation.`
	pathRoleHelpDescription = `
This path maps a Vault role name to a Keycloak username. When credentials
are requested for a role, Vault generates a new random password and sets it
on the corresponding Keycloak user via the Admin REST API.
`

	pathRoleListHelpSynopsis    = `List existing Keycloak role definitions.`
	pathRoleListHelpDescription = `Roles are listed by role name.`
)
