package secretsengine

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/vault/api"
)

// writeKVSecret PATCHes kvKey=password into the KV v2 secret at
// mountPath/secretPath using callerToken. Falls back to PUT if the secret
// does not yet exist (404). Returns a non-empty warning string and a non-nil
// error on failure; the caller must not treat this as fatal.
//
// tlsSkipVerify, when true, overrides any CA configured via env vars and
// disables certificate verification — intended only for Vault deployments that
// use a self-signed certificate and where VAULT_CACERT is not available.
func writeKVSecret(
	ctx context.Context,
	vaultAddr, callerToken, mountPath, secretPath, kvKey, password string,
	tlsSkipVerify bool,
) (string, error) {
	cfg := api.DefaultConfig()
	if cfg.Error != nil {
		return fmt.Sprintf("kv sync: failed to build Vault client config: %s", cfg.Error), cfg.Error
	}
	if vaultAddr != "" {
		cfg.Address = vaultAddr
	}
	if tlsSkipVerify {
		if err := cfg.ConfigureTLS(&api.TLSConfig{Insecure: true}); err != nil {
			return fmt.Sprintf("kv sync: failed to configure TLS: %s", err), err
		}
	}

	client, err := api.NewClient(cfg)
	if err != nil {
		return fmt.Sprintf("kv sync: failed to create Vault client: %s", err), err
	}
	client.SetToken(callerToken)

	body := map[string]interface{}{
		"data": map[string]string{
			kvKey: password,
		},
	}

	// Attempt PATCH first — preserves all other keys in the KV secret.
	kvPath := fmt.Sprintf("%s/data/%s", mountPath, secretPath)
	patchResp, err := client.Logical().JSONMergePatch(ctx, kvPath, body)
	if err == nil {
		_ = patchResp
		return "", nil
	}

	// JSONMergePatch returns an error on non-2xx; check if it is a 404 so we
	// can fall back to a PUT (create) instead.
	respErr, ok := err.(*api.ResponseError)
	if !ok || respErr.StatusCode != http.StatusNotFound {
		return fmt.Sprintf("kv sync: PATCH %s: %s", kvPath, err), err
	}

	// Secret does not exist yet — create it with a full write.
	if _, err := client.Logical().WriteWithContext(ctx, kvPath, body); err != nil {
		return fmt.Sprintf("kv sync: PUT %s: %s", kvPath, err), err
	}

	return "", nil
}
