package secretsengine

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
)

// newTestBackend returns a configured backend and in-memory storage for testing.
func newTestBackend(t *testing.T) (*keycloakBackend, logical.Storage) {
	t.Helper()

	b := backend()
	storage := &logical.InmemStorage{}

	config := &logical.BackendConfig{
		Logger: hclog.NewNullLogger(),
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: 1 * time.Hour,
			MaxLeaseTTLVal:     24 * time.Hour,
		},
		StorageView: storage,
	}

	if err := b.Setup(context.Background(), config); err != nil {
		t.Fatalf("backend setup failed: %v", err)
	}

	return b, storage
}

// --- Config path tests ---

func TestConfigWriteRead(t *testing.T) {
	b, storage := newTestBackend(t)
	ctx := context.Background()

	// Write config.
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"url":                   "https://keycloak.example.com",
			"realm":                 "master",
			"master_admin_username": "admin",
			"master_admin_password": "secret",
		},
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("config write error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("config write returned error response: %s", resp.Error().Error())
	}

	// Read config.
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("config read error: %v", err)
	}
	if resp == nil {
		t.Fatal("config read returned nil response")
		return
	}

	if resp.Data["url"] != "https://keycloak.example.com" {
		t.Errorf("expected url 'https://keycloak.example.com', got %v", resp.Data["url"])
	}
	if resp.Data["realm"] != "master" {
		t.Errorf("expected realm 'master', got %v", resp.Data["realm"])
	}
	if resp.Data["master_admin_username"] != "admin" {
		t.Errorf("expected master_admin_username 'admin', got %v", resp.Data["master_admin_username"])
	}
}

func TestConfigReadOmitsPassword(t *testing.T) {
	b, storage := newTestBackend(t)
	ctx := context.Background()

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"url":                   "https://keycloak.example.com",
			"realm":                 "master",
			"master_admin_username": "admin",
			"master_admin_password": "secret",
		},
	}
	if _, err := b.HandleRequest(ctx, req); err != nil {
		t.Fatalf("config write error: %v", err)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("config read error: %v", err)
	}
	if _, ok := resp.Data["master_admin_password"]; ok {
		t.Error("config read response must not include master_admin_password")
	}
	if _, ok := resp.Data["kv_token"]; ok {
		t.Error("config read response must not include kv_token")
	}
}

func TestConfigDelete(t *testing.T) {
	b, storage := newTestBackend(t)
	ctx := context.Background()

	// Write then delete.
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"url":                   "https://keycloak.example.com",
			"realm":                 "master",
			"master_admin_username": "admin",
			"master_admin_password": "secret",
		},
	}
	if _, err := b.HandleRequest(ctx, req); err != nil {
		t.Fatalf("config write error: %v", err)
	}

	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "config",
		Storage:   storage,
	}
	if _, err := b.HandleRequest(ctx, req); err != nil {
		t.Fatalf("config delete error: %v", err)
	}

	// Verify config is gone.
	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("config read after delete error: %v", err)
	}
	if resp != nil {
		t.Error("expected nil response after config delete")
	}
}

// --- Role path tests ---

func TestRoleWriteRead(t *testing.T) {
	b, storage := newTestBackend(t)
	ctx := context.Background()

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/myrole",
		Storage:   storage,
		Data: map[string]interface{}{
			"keycloak_username": "testuser",
			"ttl":               7200,
			"max_ttl":           86400,
		},
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("role write error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("role write returned error response: %s", resp.Error().Error())
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/myrole",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("role read error: %v", err)
	}
	if resp == nil {
		t.Fatal("role read returned nil response")
		return
	}
	if resp.Data["keycloak_username"] != "testuser" {
		t.Errorf("expected keycloak_username 'testuser', got %v", resp.Data["keycloak_username"])
	}
}

func TestRoleList(t *testing.T) {
	b, storage := newTestBackend(t)
	ctx := context.Background()

	for _, name := range []string{"alpha", "bravo"} {
		req := &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "roles/" + name,
			Storage:   storage,
			Data: map[string]interface{}{
				"keycloak_username": name + "-user",
			},
		}
		if _, err := b.HandleRequest(ctx, req); err != nil {
			t.Fatalf("role write error: %v", err)
		}
	}

	req := &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("role list error: %v", err)
	}
	keys, ok := resp.Data["keys"].([]string)
	if !ok {
		t.Fatal("role list did not return keys")
	}
	if len(keys) != 2 {
		t.Errorf("expected 2 roles, got %d", len(keys))
	}
}

func TestRoleDelete(t *testing.T) {
	b, storage := newTestBackend(t)
	ctx := context.Background()

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/ephemeral",
		Storage:   storage,
		Data: map[string]interface{}{
			"keycloak_username": "someuser",
		},
	}
	if _, err := b.HandleRequest(ctx, req); err != nil {
		t.Fatalf("role write error: %v", err)
	}

	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/ephemeral",
		Storage:   storage,
	}
	if _, err := b.HandleRequest(ctx, req); err != nil {
		t.Fatalf("role delete error: %v", err)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/ephemeral",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("role read after delete error: %v", err)
	}
	if resp != nil {
		t.Error("expected nil response after role delete")
	}
}

func TestRoleMissingUsername(t *testing.T) {
	b, storage := newTestBackend(t)
	ctx := context.Background()

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/bad",
		Storage:   storage,
		Data:      map[string]interface{}{},
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("role write error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response for missing keycloak_username")
	}
}

func TestRoleTTLExceedsMaxTTL(t *testing.T) {
	b, storage := newTestBackend(t)
	ctx := context.Background()

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/bad-ttl",
		Storage:   storage,
		Data: map[string]interface{}{
			"keycloak_username": "someuser",
			"ttl":               86400,
			"max_ttl":           3600,
		},
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("role write error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response when ttl > max_ttl")
	}
}

func TestRoleWithKVPasswordKey(t *testing.T) {
	b, storage := newTestBackend(t)
	ctx := context.Background()

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/kv-role",
		Storage:   storage,
		Data: map[string]interface{}{
			"keycloak_username": "testuser",
			"kv_password_key":   "my-password-key",
		},
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("role write error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("role write returned error response: %s", resp.Error().Error())
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/kv-role",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("role read error: %v", err)
	}
	if resp == nil {
		t.Fatal("role read returned nil response")
		return
	}
	if resp.Data["kv_password_key"] != "my-password-key" {
		t.Errorf("expected kv_password_key 'my-password-key', got %v", resp.Data["kv_password_key"])
	}
}

func TestConfigWithKVFields(t *testing.T) {
	b, storage := newTestBackend(t)
	ctx := context.Background()

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data: map[string]interface{}{
			"url":                   "https://keycloak.example.com",
			"master_admin_username": "admin",
			"master_admin_password": "secret",
			"kv_mount_path":         "k8s",
			"kv_secret_path":        "keycloak/realm-users",
			"kv_api_addr":           "https://vault.local:8200",
			"kv_tls_skip_verify":    true,
		},
	}
	if _, err := b.HandleRequest(ctx, req); err != nil {
		t.Fatalf("config write error: %v", err)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("config read error: %v", err)
	}
	if resp.Data["realm"] != "master" {
		t.Errorf("expected realm to default to 'master', got %v", resp.Data["realm"])
	}
	if resp.Data["kv_mount_path"] != "k8s" {
		t.Errorf("expected kv_mount_path 'k8s', got %v", resp.Data["kv_mount_path"])
	}
	if resp.Data["kv_secret_path"] != "keycloak/realm-users" {
		t.Errorf("expected kv_secret_path 'keycloak/realm-users', got %v", resp.Data["kv_secret_path"])
	}
	if resp.Data["kv_api_addr"] != "https://vault.local:8200" {
		t.Errorf("expected kv_api_addr 'https://vault.local:8200', got %v", resp.Data["kv_api_addr"])
	}
	if resp.Data["kv_tls_skip_verify"] != true {
		t.Errorf("expected kv_tls_skip_verify true, got %v", resp.Data["kv_tls_skip_verify"])
	}
}

// TestFactory covers the plugin entry point Vault calls to load the backend.
func TestFactory(t *testing.T) {
	b, err := Factory(context.Background(), &logical.BackendConfig{
		Logger:      hclog.NewNullLogger(),
		System:      &logical.StaticSystemView{},
		StorageView: &logical.InmemStorage{},
	})
	if err != nil {
		t.Fatalf("Factory returned error: %v", err)
	}
	if b == nil {
		t.Fatal("Factory returned a nil backend")
	}
}
