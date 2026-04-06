package secretsengine

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// usernamePattern covers letters, digits, dots, hyphens, plus signs, and @ —
// the common Keycloak username and email-style username formats.
const usernamePattern = `(?P<username>[a-zA-Z0-9_.@+-]+)`

// pathUsers registers the /users endpoints on the backend.
func pathUsers(b *keycloakBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "users/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathUsersList,
					Summary:  "List all users in the configured Keycloak target realm.",
				},
			},
			HelpSynopsis:    pathUsersListHelpSynopsis,
			HelpDescription: pathUsersListHelpDescription,
		},
		{
			Pattern: "users/" + usernamePattern + "$",
			Fields: map[string]*framework.FieldSchema{
				"username": {
					Type:        framework.TypeString,
					Description: "Keycloak username.",
					Required:    true,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathUsersRead,
					Summary:  "Read a Keycloak user's details.",
				},
			},
			HelpSynopsis:    pathUsersReadHelpSynopsis,
			HelpDescription: pathUsersReadHelpDescription,
		},
		{
			Pattern: "users/" + usernamePattern + "/rotate$",
			Fields: map[string]*framework.FieldSchema{
				"username": {
					Type:        framework.TypeString,
					Description: "Keycloak username whose password will be rotated.",
					Required:    true,
				},
				"kv_password_key": {
					Type:        framework.TypeString,
					Description: "KV v2 key to PATCH with the new password after rotation. Optional; omit to skip KV sync.",
					Required:    false,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathUsersRotate,
					Summary:  "Rotate the password for a Keycloak user and return the new value.",
				},
			},
			HelpSynopsis:    pathUsersRotateHelpSynopsis,
			HelpDescription: pathUsersRotateHelpDescription,
		},
	}
}

func (b *keycloakBackend) pathUsersList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	users, err := client.ListUsers(ctx)
	if err != nil {
		return nil, err
	}

	usernames := make([]string, 0, len(users))
	for _, u := range users {
		usernames = append(usernames, u.Username)
	}
	return logical.ListResponse(usernames), nil
}

func (b *keycloakBackend) pathUsersRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	username := data.Get("username").(string)

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	user, err := client.GetUser(ctx, username)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return logical.ErrorResponse("user %q not found in target realm", username), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"username":   user.Username,
			"id":         user.ID,
			"enabled":    user.Enabled,
			"email":      user.Email,
			"first_name": user.FirstName,
			"last_name":  user.LastName,
		},
	}, nil
}

func (b *keycloakBackend) pathUsersRotate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	username := data.Get("username").(string)

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	password, err := generatePassword()
	if err != nil {
		return nil, fmt.Errorf("error generating password: %w", err)
	}

	if err := client.ResetPassword(ctx, username, password); err != nil {
		b.Logger().Error("failed to rotate password",
			"keycloak_username", username,
			"error", err,
		)
		return nil, fmt.Errorf("error rotating password for user %q: %w", username, err)
	}

	b.Logger().Info("password rotated successfully",
		"keycloak_username", username,
	)

	// Update static-creds storage for any non-ephemeral roles that map to this
	// username, resetting their autorotation timer.
	if syncErr := b.syncStaticCredsForUsername(ctx, req.Storage, username, password); syncErr != nil {
		b.Logger().Error("failed to sync static creds after manual rotation",
			"keycloak_username", username,
			"error", syncErr,
		)
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"username": username,
			"password": password,
		},
	}

	kvKey, _ := data.GetOk("kv_password_key")
	if kvKey != nil && kvKey.(string) != "" {
		config, err := getConfig(ctx, req.Storage)
		if err == nil && config != nil && config.KVMountPath != "" && config.KVSecretPath != "" {
			if config.KVToken == "" {
				resp.Warnings = append(resp.Warnings, "kv sync skipped: kv_token not configured")
			} else {
				vaultAddr := config.KVAPIAddr
				if vaultAddr == "" {
					vaultAddr = "https://127.0.0.1:8200"
				}
				if warning, err := writeKVSecret(ctx, vaultAddr, config.KVToken, config.KVMountPath, config.KVSecretPath, kvKey.(string), password, config.KVTLSSkipVerify); err != nil {
					b.Logger().Error("kv sync failed after password rotation",
						"keycloak_username", username,
						"kv_mount_path", config.KVMountPath,
						"kv_secret_path", config.KVSecretPath,
						"kv_password_key", kvKey.(string),
						"error", err,
					)
					resp.Warnings = append(resp.Warnings, warning)
				} else {
					b.Logger().Info("kv secret updated successfully",
						"keycloak_username", username,
						"kv_secret_path", config.KVSecretPath,
						"kv_password_key", kvKey.(string),
					)
				}
			}
		}
	}

	return resp, nil
}

const (
	pathUsersListHelpSynopsis    = `List all users in the configured Keycloak target realm.`
	pathUsersListHelpDescription = `
Returns the usernames of all users in the target realm (up to 500).
Use 'read users/<username>' to view a user's details, or
'write users/<username>/rotate' to rotate their password.
`
	pathUsersReadHelpSynopsis    = `Read a Keycloak user's details.`
	pathUsersReadHelpDescription = `
Returns the Keycloak user's username, internal ID, enabled status,
email, first name, and last name.
`
	pathUsersRotateHelpSynopsis    = `Rotate the password for a Keycloak user.`
	pathUsersRotateHelpDescription = `
Generates a new random password, sets it on the specified Keycloak
user via the Admin REST API, and returns it. The password is not
stored anywhere — save it before navigating away.
`
)
