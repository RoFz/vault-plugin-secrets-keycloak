package secretsengine

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const keycloakPasswordType = "keycloak_password"

// pathCredentials registers the /creds/<name> endpoint.
func pathCredentials(b *keycloakBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the role to generate credentials for.",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathCredentialsRead,
				Summary:  "Generate a new password for the Keycloak user bound to this role.",
			},
		},
		HelpSynopsis:    pathCredentialsHelpSyn,
		HelpDescription: pathCredentialsHelpDesc,
	}
}

// pathCredentialsRead generates a random password, sets it on Keycloak, and
// returns it as a Vault secret with a managed lease.
func (b *keycloakBackend) pathCredentialsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role %q not found", roleName), nil
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	password, err := generatePassword()
	if err != nil {
		return nil, fmt.Errorf("error generating password: %w", err)
	}

	if err := client.ResetPassword(ctx, role.KeycloakUsername, password); err != nil {
		b.Logger().Error("failed to rotate password",
			"role", roleName,
			"keycloak_username", role.KeycloakUsername,
			"error", err,
		)
		return nil, fmt.Errorf("error rotating password for user %q: %w", role.KeycloakUsername, err)
	}
	b.Logger().Info("password rotated successfully",
		"role", roleName,
		"keycloak_username", role.KeycloakUsername,
	)

	resp := b.Secret(keycloakPasswordType).Response(
		// Public data returned to the caller.
		map[string]interface{}{
			"username": role.KeycloakUsername,
			"password": password,
		},
		// Internal data used during revoke/renew — never exposed to callers.
		map[string]interface{}{
			"role":              roleName,
			"keycloak_username": role.KeycloakUsername,
		},
	)

	if role.TTL > 0 {
		resp.Secret.TTL = role.TTL
	}
	if role.MaxTTL > 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}

	return resp, nil
}

// keycloakSecret defines the secret type and its revoke/renew lifecycle callbacks.
func keycloakSecret(b *keycloakBackend) *framework.Secret {
	return &framework.Secret{
		Type: keycloakPasswordType,
		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:        framework.TypeString,
				Description: "Keycloak username.",
			},
			"password": {
				Type:        framework.TypeString,
				Description: "Generated password set on the Keycloak user.",
			},
		},
		Revoke: b.secretRevoke,
		Renew:  b.secretRenew,
	}
}

// secretRevoke rotates the Keycloak password to a fresh discarded value,
// invalidating the previously issued credential.
func (b *keycloakBackend) secretRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	username, ok := req.Secret.InternalData["keycloak_username"].(string)
	if !ok || username == "" {
		return nil, fmt.Errorf("internal data missing keycloak_username")
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	discardedPassword, err := generatePassword()
	if err != nil {
		return nil, fmt.Errorf("error generating revocation password: %w", err)
	}

	if err := client.ResetPassword(ctx, username, discardedPassword); err != nil {
		return nil, fmt.Errorf("error revoking credential for user %q: %w", username, err)
	}

	return nil, nil
}

// secretRenew extends the lease TTL without rotating the password.
func (b *keycloakBackend) secretRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName, ok := req.Secret.InternalData["role"].(string)
	if !ok || roleName == "" {
		return nil, fmt.Errorf("internal data missing role")
	}

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, fmt.Errorf("role %q not found during renewal", roleName)
	}

	resp := &logical.Response{Secret: req.Secret}
	if role.TTL > 0 {
		resp.Secret.TTL = role.TTL
	}
	if role.MaxTTL > 0 {
		resp.Secret.MaxTTL = role.MaxTTL
	}

	return resp, nil
}

const pathCredentialsHelpSyn = `Generate a Keycloak user password from a specific Vault role.`

const pathCredentialsHelpDesc = `
This path generates a random password and immediately sets it on the Keycloak
user associated with the given role. The previous password is replaced.

On lease revocation, the password is rotated again to a discarded random value,
invalidating the credential that was issued.
`
