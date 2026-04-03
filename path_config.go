package secretsengine

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const configStoragePath = "config"

// keycloakConfig holds the minimum configuration needed to call the Keycloak Admin API.
type keycloakConfig struct {
	URL         string `json:"url"`
	Realm       string `json:"realm"`
	TargetRealm string `json:"target_realm"`
	ClientID    string `json:"client_id"`
	Username    string `json:"username"`
	Password    string `json:"password"`
}

// pathConfig registers the /config endpoint on the backend.
func pathConfig(b *keycloakBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"url": {
				Type:        framework.TypeString,
				Description: "Base URL of the Keycloak server, e.g. https://keycloak.example.com.",
				Required:    true,
			},
			"realm": {
				Type:        framework.TypeString,
				Description: "Auth realm used to obtain admin tokens (typically \"master\").",
				Required:    true,
			},
			"target_realm": {
				Type:        framework.TypeString,
				Description: "Realm whose users will be managed (e.g. \"myrealm\"). Defaults to realm if not set.",
				Required:    false,
			},
			"client_id": {
				Type:        framework.TypeString,
				Description: "OIDC client used to obtain admin tokens. Defaults to \"admin-cli\".",
				Required:    false,
			},
			"username": {
				Type:        framework.TypeString,
				Description: "Keycloak admin username (e.g. \"admin\").",
				Required:    true,
			},
			"password": {
				Type:        framework.TypeString,
				Description: "Password for the admin user.",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Sensitive: true,
				},
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
				Summary:  "Read the Keycloak backend configuration.",
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
				Summary:  "Create or update the Keycloak backend configuration.",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
				Summary:  "Create or update the Keycloak backend configuration.",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
				Summary:  "Delete the Keycloak backend configuration.",
			},
		},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    pathConfigHelpSynopsis,
		HelpDescription: pathConfigHelpDescription,
	}
}

func (b *keycloakBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, configStoragePath)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}
	return out != nil, nil
}

func (b *keycloakBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return nil, nil
	}

	// password is intentionally omitted from the read response.
	return &logical.Response{
		Data: map[string]interface{}{
			"url":          config.URL,
			"realm":        config.Realm,
			"target_realm": config.TargetRealm,
			"client_id":    config.ClientID,
			"username":     config.Username,
		},
	}, nil
}

func (b *keycloakBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		config = &keycloakConfig{}
	}

	if v, ok := data.GetOk("url"); ok {
		config.URL = v.(string)
	}
	if v, ok := data.GetOk("realm"); ok {
		config.Realm = v.(string)
	}
	if v, ok := data.GetOk("target_realm"); ok {
		config.TargetRealm = v.(string)
	}
	if v, ok := data.GetOk("client_id"); ok {
		config.ClientID = v.(string)
	}
	if v, ok := data.GetOk("username"); ok {
		config.Username = v.(string)
	}
	if v, ok := data.GetOk("password"); ok {
		config.Password = v.(string)
	}

	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	b.reset()

	// Test connectivity immediately so the operator gets feedback at config time.
	// The write succeeds regardless — Keycloak may not be reachable yet.
	targetRealm := config.TargetRealm
	if targetRealm == "" {
		targetRealm = config.Realm
	}
	client, err := newClient(config)
	if err != nil {
		b.Logger().Error("keycloak config saved but client could not be created",
			"url", config.URL,
			"realm", config.Realm,
			"target_realm", targetRealm,
			"username", config.Username,
			"error", err,
		)
	} else if _, err := client.getAdminToken(ctx); err != nil {
		b.Logger().Error("keycloak config saved but connection test failed",
			"url", config.URL,
			"realm", config.Realm,
			"target_realm", targetRealm,
			"username", config.Username,
			"error", err,
		)
	} else {
		b.Logger().Info("keycloak config saved and connection test succeeded",
			"url", config.URL,
			"realm", config.Realm,
			"target_realm", targetRealm,
			"username", config.Username,
		)
	}

	return nil, nil
}

func (b *keycloakBackend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, configStoragePath); err != nil {
		return nil, err
	}
	b.reset()
	return nil, nil
}

// getConfig loads the stored configuration from Vault storage.
func getConfig(ctx context.Context, s logical.Storage) (*keycloakConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	config := new(keycloakConfig)
	if err := entry.DecodeJSON(config); err != nil {
		return nil, fmt.Errorf("error decoding configuration: %w", err)
	}
	return config, nil
}

const pathConfigHelpSynopsis = `Configure the Keycloak secrets backend.`

const pathConfigHelpDescription = `
The Keycloak secrets backend authenticates as a named admin user via the
Resource Owner Password Credentials (ROPC) grant and then manages users
in the target realm.

The built-in "admin-cli" client in the master realm supports this flow
without requiring a client secret. Write the configuration as follows:

  vault write keycloak/config \
    url="https://keycloak.example.com" \
    realm="master" \
    target_realm="myrealm" \
    username="admin" \
    password="<admin-password>"

client_id defaults to "admin-cli" if omitted.
If target_realm is omitted it defaults to the value of realm.
`
