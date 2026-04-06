package secretsengine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

// writeRole stores an ephemeral role mapping name -> keycloak_username,
// merging any extra fields. All creds-lifecycle tests exercise the ephemeral
// lease path, so the role defaults to ephemeral=true with valid ttl bounds.
func writeRole(t *testing.T, b *keycloakBackend, storage logical.Storage, name, username string, extra map[string]interface{}) {
	t.Helper()
	data := map[string]interface{}{
		"keycloak_username": username,
		"ephemeral":         true,
		"ttl":               3600,
		"max_ttl":           86400,
	}
	for k, v := range extra {
		data[k] = v
	}
	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/" + name,
		Storage:   storage,
		Data:      data,
	}); err != nil {
		t.Fatalf("role write error: %v", err)
	}
}

// readCreds reads creds/<role> and returns the response.
func readCreds(t *testing.T, b *keycloakBackend, storage logical.Storage, role string) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/" + role,
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("creds read error: %v", err)
	}
	if resp == nil {
		t.Fatal("creds read returned nil response")
	}
	return resp
}

func TestCredsRead_RotatesAndReturnsSecret(t *testing.T) {
	kc := &fakeKC{}
	url := startFakeKC(t, kc)
	b, storage := newTestBackend(t)
	configureBackend(t, b, storage, baseConfig(url))
	writeRole(t, b, storage, "app", "alice", nil)

	resp := readCreds(t, b, storage, "app")

	if resp.Data["username"] != "alice" {
		t.Errorf("expected username alice, got %v", resp.Data["username"])
	}
	if pw, _ := resp.Data["password"].(string); pw == "" {
		t.Error("expected a non-empty password")
	}
	if resp.Secret == nil {
		t.Fatal("creds read must return a Vault secret (lease)")
	}
	if kc.resets() == 0 {
		t.Error("issuing credentials must reset the Keycloak password")
	}
}

// TestCredsRead_ResponseOmitsSecrets locks the invariant that the credential
// response never exposes internal lifecycle data or configured secrets.
func TestCredsRead_ResponseOmitsSecrets(t *testing.T) {
	url := startFakeKC(t, &fakeKC{})
	b, storage := newTestBackend(t)
	configureBackend(t, b, storage, baseConfig(url))
	writeRole(t, b, storage, "app", "alice", nil)

	resp := readCreds(t, b, storage, "app")

	for _, leaked := range []string{"role", "keycloak_username", "master_admin_password", "kv_token"} {
		if _, ok := resp.Data[leaked]; ok {
			t.Errorf("credential response must not expose %q in Data", leaked)
		}
	}
	// The internal data (used only for revoke/renew) carries keycloak_username,
	// but it lives on Secret.InternalData, never in the caller-visible Data.
	if resp.Secret == nil || resp.Secret.InternalData["keycloak_username"] != "alice" {
		t.Error("expected keycloak_username to be retained in Secret.InternalData for revocation")
	}
}

// TestSecretRevoke_RotatesToDiscardedPassword is the core security guarantee:
// revoking a lease must rotate the Keycloak password (invalidating the issued
// credential), not merely succeed silently.
func TestSecretRevoke_RotatesToDiscardedPassword(t *testing.T) {
	kc := &fakeKC{}
	url := startFakeKC(t, kc)
	b, storage := newTestBackend(t)
	configureBackend(t, b, storage, baseConfig(url))

	before := kc.resets()
	if _, err := b.secretRevoke(context.Background(), &logical.Request{
		Storage: storage,
		Secret: &logical.Secret{
			InternalData: map[string]interface{}{"keycloak_username": "alice"},
		},
	}, nil); err != nil {
		t.Fatalf("revoke error: %v", err)
	}
	if got := kc.resets(); got != before+1 {
		t.Fatalf("revoke must rotate the password exactly once; resets %d -> %d", before, got)
	}
}

// TestSecretRevoke_MissingUsernameFailsClosed ensures a revoke with no username
// errors rather than silently succeeding (which would leave a live credential).
func TestSecretRevoke_MissingUsernameFailsClosed(t *testing.T) {
	url := startFakeKC(t, &fakeKC{})
	b, storage := newTestBackend(t)
	configureBackend(t, b, storage, baseConfig(url))

	if _, err := b.secretRevoke(context.Background(), &logical.Request{
		Storage: storage,
		Secret:  &logical.Secret{InternalData: map[string]interface{}{}},
	}, nil); err == nil {
		t.Fatal("revoke must fail closed when keycloak_username is missing")
	}
}

// TestSecretRenew_ExtendsTTLWithoutRotation: renew extends the lease using the
// role's TTL and must NOT rotate the password.
func TestSecretRenew_ExtendsTTLWithoutRotation(t *testing.T) {
	kc := &fakeKC{}
	url := startFakeKC(t, kc)
	b, storage := newTestBackend(t)
	configureBackend(t, b, storage, baseConfig(url))
	writeRole(t, b, storage, "app", "alice", map[string]interface{}{"ttl": 1800, "max_ttl": 7200})

	before := kc.resets()
	resp, err := b.secretRenew(context.Background(), &logical.Request{
		Storage: storage,
		Secret:  &logical.Secret{InternalData: map[string]interface{}{"role": "app"}},
	}, nil)
	if err != nil {
		t.Fatalf("renew error: %v", err)
	}
	if resp == nil || resp.Secret == nil {
		t.Fatal("renew must return the secret with refreshed TTLs")
	}
	if resp.Secret.TTL != 1800*time.Second {
		t.Errorf("expected renewed TTL 30m, got %v", resp.Secret.TTL)
	}
	if got := kc.resets(); got != before {
		t.Errorf("renew must NOT rotate the password; resets %d -> %d", before, got)
	}
}

func TestSecretRenew_MissingRoleErrors(t *testing.T) {
	url := startFakeKC(t, &fakeKC{})
	b, storage := newTestBackend(t)
	configureBackend(t, b, storage, baseConfig(url))

	if _, err := b.secretRenew(context.Background(), &logical.Request{
		Storage: storage,
		Secret:  &logical.Secret{InternalData: map[string]interface{}{"role": "ghost"}},
	}, nil); err == nil {
		t.Fatal("renew must error when the backing role no longer exists")
	}
}

// TestCredsRead_AuthErrorDoesNotLeakPassword: when admin auth fails, the error
// surfaced to the caller must not contain the configured admin password.
func TestCredsRead_AuthErrorDoesNotLeakPassword(t *testing.T) {
	url := startFakeKC(t, &fakeKC{tokenStatus: http.StatusUnauthorized})
	b, storage := newTestBackend(t)
	configureBackend(t, b, storage, baseConfig(url))
	writeRole(t, b, storage, "app", "alice", nil)

	_, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/app",
		Storage:   storage,
	})
	if err == nil {
		t.Fatal("expected creds read to fail when admin auth fails")
	}
	if strings.Contains(err.Error(), testAdminPassword) {
		t.Fatalf("error leaked the admin password: %v", err)
	}
}

// TestCredsRead_KVSyncFailureIsNonFatal: a KV-sync failure after a successful
// rotation must NOT fail credential issuance, must still return the password,
// and the warning must not leak the generated password.
func TestCredsRead_KVSyncFailureIsNonFatal(t *testing.T) {
	url := startFakeKC(t, &fakeKC{})
	// A fake Vault KV endpoint that rejects the write (403 => no client retries,
	// realistic for a kv_token lacking permission on the data path).
	kvDown := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "permission denied", http.StatusForbidden)
	}))
	t.Cleanup(kvDown.Close)

	b, storage := newTestBackend(t)
	cfg := baseConfig(url)
	cfg["kv_mount_path"] = "secret"
	cfg["kv_secret_path"] = "keycloak/app"
	cfg["kv_api_addr"] = kvDown.URL
	cfg["kv_token"] = "kv-token-xyz"
	configureBackend(t, b, storage, cfg)
	writeRole(t, b, storage, "app", "alice", map[string]interface{}{"kv_password_key": "password"})

	resp := readCreds(t, b, storage, "app")

	pw, _ := resp.Data["password"].(string)
	if pw == "" {
		t.Fatal("password must still be returned when KV sync fails")
	}
	if len(resp.Warnings) == 0 {
		t.Fatal("expected a warning describing the KV sync failure")
	}
	for _, warn := range resp.Warnings {
		if strings.Contains(warn, pw) {
			t.Fatalf("KV-sync warning leaked the generated password: %q", warn)
		}
	}
}

// TestCredsRead_KVSyncSkippedWithoutToken: KV fields set but no kv_token => the
// sync is skipped with a warning, and issuance still succeeds.
func TestCredsRead_KVSyncSkippedWithoutToken(t *testing.T) {
	url := startFakeKC(t, &fakeKC{})
	b, storage := newTestBackend(t)
	cfg := baseConfig(url)
	cfg["kv_mount_path"] = "secret"
	cfg["kv_secret_path"] = "keycloak/app"
	configureBackend(t, b, storage, cfg)
	writeRole(t, b, storage, "app", "alice", map[string]interface{}{"kv_password_key": "password"})

	resp := readCreds(t, b, storage, "app")

	if pw, _ := resp.Data["password"].(string); pw == "" {
		t.Fatal("password must still be returned when KV sync is skipped")
	}
	found := false
	for _, warn := range resp.Warnings {
		if strings.Contains(warn, "kv_token") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a warning about the missing kv_token, got %v", resp.Warnings)
	}
}
