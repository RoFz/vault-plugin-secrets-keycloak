package secretsengine

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// These tests drive the /users paths in-process against the fake Keycloak,
// exercising the path handlers and the client.go HTTP methods without a real
// Keycloak, a real Vault, or the plugin subprocess.

func TestUsersList_FakeKeycloak(t *testing.T) {
	url := startFakeKC(t, &fakeKC{})
	b, storage := newTestBackend(t)
	configureBackend(t, b, storage, baseConfig(url))

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "users/",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("users list error: %v", err)
	}
	keys, _ := resp.Data["keys"].([]string)
	if len(keys) != 1 || keys[0] != "alice" {
		t.Fatalf("expected [alice], got %v", resp.Data["keys"])
	}
}

func TestUsersRead_FakeKeycloak(t *testing.T) {
	url := startFakeKC(t, &fakeKC{})
	b, storage := newTestBackend(t)
	configureBackend(t, b, storage, baseConfig(url))

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "users/alice",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("users read error: %v", err)
	}
	if resp.Data["username"] != "alice" {
		t.Fatalf("expected username alice, got %v", resp.Data["username"])
	}
}

func TestUsersRead_NotFoundReturnsErrorResponse(t *testing.T) {
	// Empty user list => GetUser returns nil => handler returns an error response.
	url := startFakeKC(t, &fakeKC{usersBody: "[]"})
	b, storage := newTestBackend(t)
	configureBackend(t, b, storage, baseConfig(url))

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "users/ghost",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("unexpected hard error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected a not-found error response, got %#v", resp)
	}
}

func TestUsersList_KeycloakErrorSurfaces(t *testing.T) {
	// A 403 from Keycloak must surface as an error, not an empty success.
	url := startFakeKC(t, &fakeKC{usersStatus: http.StatusForbidden})
	b, storage := newTestBackend(t)
	configureBackend(t, b, storage, baseConfig(url))

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "users/",
		Storage:   storage,
	}); err == nil {
		t.Fatal("expected list users to surface the Keycloak 403")
	}
}

func TestUsersRotate_FakeKeycloak(t *testing.T) {
	kc := &fakeKC{}
	url := startFakeKC(t, kc)
	b, storage := newTestBackend(t)
	configureBackend(t, b, storage, baseConfig(url))

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "users/alice/rotate",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("users rotate error: %v", err)
	}
	if pw, _ := resp.Data["password"].(string); pw == "" {
		t.Fatal("expected a non-empty rotated password")
	}
	if resp.Data["username"] != "alice" {
		t.Fatalf("expected username alice, got %v", resp.Data["username"])
	}
	if kc.resets() == 0 {
		t.Fatal("rotate must issue a reset-password to Keycloak")
	}
}

// TestUsersRotate_KVSyncFailureIsNonFatal: the on-demand rotate endpoint takes
// kv_password_key as a REQUEST parameter (distinct from the role-config path in
// creds). A KV-sync failure must still return the rotated password with a
// warning, and the warning must not leak the password.
func TestUsersRotate_KVSyncFailureIsNonFatal(t *testing.T) {
	kc := &fakeKC{}
	kcURL := startFakeKC(t, kc)
	kvDown := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "permission denied", http.StatusForbidden)
	}))
	t.Cleanup(kvDown.Close)

	b, storage := newTestBackend(t)
	cfg := baseConfig(kcURL)
	cfg["kv_mount_path"] = "secret"
	cfg["kv_secret_path"] = "keycloak/app"
	cfg["kv_api_addr"] = kvDown.URL
	cfg["kv_token"] = "kv-token-xyz"
	configureBackend(t, b, storage, cfg)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "users/alice/rotate",
		Storage:   storage,
		Data:      map[string]interface{}{"kv_password_key": "password"},
	})
	if err != nil {
		t.Fatalf("KV failure must not fail the rotation: %v", err)
	}
	pw, _ := resp.Data["password"].(string)
	if pw == "" {
		t.Fatal("password must still be returned when KV sync fails")
	}
	if len(resp.Warnings) == 0 {
		t.Fatal("expected a warning describing the KV sync failure")
	}
	for _, warn := range resp.Warnings {
		if strings.Contains(warn, pw) {
			t.Fatalf("KV-sync warning leaked the rotated password: %q", warn)
		}
	}
}

// TestUsersRotate_KVSyncSkippedWithoutToken: kv_password_key given and KV paths
// configured, but no kv_token => the sync is skipped with a warning, and the
// rotation still returns the password.
func TestUsersRotate_KVSyncSkippedWithoutToken(t *testing.T) {
	kc := &fakeKC{}
	kcURL := startFakeKC(t, kc)
	b, storage := newTestBackend(t)
	cfg := baseConfig(kcURL)
	cfg["kv_mount_path"] = "secret"
	cfg["kv_secret_path"] = "keycloak/app"
	configureBackend(t, b, storage, cfg)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "users/alice/rotate",
		Storage:   storage,
		Data:      map[string]interface{}{"kv_password_key": "password"},
	})
	if err != nil {
		t.Fatalf("rotate error: %v", err)
	}
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
