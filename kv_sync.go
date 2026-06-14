package secretsengine

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/sdk/logical"
)

// defaultKVAddr is the Vault API address used for KV sync when kv_api_addr is
// not configured.
const defaultKVAddr = "https://127.0.0.1:8200"

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

// syncKVForResponse PATCHes the freshly rotated password into the configured
// KV v2 secret and returns warnings to surface in the caller's response. It
// returns nil when no KV sync applies (no key, or KV not configured), and a
// single warning when the sync is skipped (no kv_token) or fails. The variadic
// logFields carry caller identity (role and/or keycloak_username) for the
// success and failure log lines.
func (b *keycloakBackend) syncKVForResponse(ctx context.Context, s logical.Storage, kvKey, password string, logFields ...interface{}) []string {
	if kvKey == "" {
		return nil
	}
	config, err := getConfig(ctx, s)
	if err != nil || config == nil || config.KVMountPath == "" || config.KVSecretPath == "" {
		return nil
	}
	if config.KVToken == "" {
		return []string{"kv sync skipped: kv_token not configured"}
	}
	addr := config.KVAPIAddr
	if addr == "" {
		addr = defaultKVAddr
	}

	fields := make([]interface{}, 0, len(logFields)+8)
	fields = append(fields, logFields...)
	fields = append(fields,
		"kv_mount_path", config.KVMountPath,
		"kv_secret_path", config.KVSecretPath,
		"kv_password_key", kvKey,
	)

	warning, err := writeKVSecret(ctx, addr, config.KVToken, config.KVMountPath, config.KVSecretPath, kvKey, password, config.KVTLSSkipVerify)
	if err != nil {
		b.Logger().Error("kv sync failed after password rotation", append(fields, "error", err)...)
		return []string{warning}
	}
	b.Logger().Info("kv secret updated successfully", fields...)
	return nil
}
