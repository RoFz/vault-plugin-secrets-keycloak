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
	TTL              time.Duration `json:"ttl"`
	MaxTTL           time.Duration `json:"max_ttl"`
	KVPasswordKey    string        `json:"kv_password_key"`
}

// toResponseData returns the role fields safe to show in a read response.
func (r *keycloakRoleEntry) toResponseData() map[string]interface{} {
	return map[string]interface{}{
		"keycloak_username": r.KeycloakUsername,
		"ttl":               r.TTL.Seconds(),
		"max_ttl":           r.MaxTTL.Seconds(),
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
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Lease duration before the credential is automatically revoked. Defaults to 1 hour.",
					Default:     3600,
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum lease duration. Defaults to 24 hours.",
					Default:     86400,
				},
				"kv_password_key": {
					Type:        framework.TypeString,
					Description: "KV v2 key to PATCH with the new password after rotation via creds/<role>. Optional.",
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
	role, err := b.getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		role = &keycloakRoleEntry{}
	}

	if v, ok := data.GetOk("keycloak_username"); ok {
		role.KeycloakUsername = v.(string)
	}
	if role.KeycloakUsername == "" {
		return logical.ErrorResponse("keycloak_username is required"), nil
	}

	if v, ok := data.GetOk("ttl"); ok {
		role.TTL = time.Duration(v.(int)) * time.Second
	}
	if v, ok := data.GetOk("max_ttl"); ok {
		role.MaxTTL = time.Duration(v.(int)) * time.Second
	}
	if role.MaxTTL > 0 && role.TTL > role.MaxTTL {
		return logical.ErrorResponse("ttl cannot exceed max_ttl"), nil
	}
	if v, ok := data.GetOk("kv_password_key"); ok {
		role.KVPasswordKey = v.(string)
	}

	return nil, b.setRole(ctx, req.Storage, name, role)
}

func (b *keycloakBackend) pathRoleDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, "roles/"+data.Get("name").(string)); err != nil {
		return nil, err
	}
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
