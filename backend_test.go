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
			"url":      "https://keycloak.example.com",
			"realm":    "master",
			"username": "admin",
			"password": "secret",
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
	}

	if resp.Data["url"] != "https://keycloak.example.com" {
		t.Errorf("expected url 'https://keycloak.example.com', got %v", resp.Data["url"])
	}
	if resp.Data["realm"] != "master" {
		t.Errorf("expected realm 'master', got %v", resp.Data["realm"])
	}
	if resp.Data["username"] != "admin" {
		t.Errorf("expected username 'admin', got %v", resp.Data["username"])
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
			"url":      "https://keycloak.example.com",
			"realm":    "master",
			"username": "admin",
			"password": "secret",
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
	if _, ok := resp.Data["password"]; ok {
		t.Error("config read response must not include password")
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
			"url":      "https://keycloak.example.com",
			"realm":    "master",
			"username": "admin",
			"password": "secret",
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
		Path:      "role/myrole",
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
		Path:      "role/myrole",
		Storage:   storage,
	}
	resp, err = b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("role read error: %v", err)
	}
	if resp == nil {
		t.Fatal("role read returned nil response")
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
			Path:      "role/" + name,
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
		Path:      "role/",
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
		Path:      "role/ephemeral",
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
		Path:      "role/ephemeral",
		Storage:   storage,
	}
	if _, err := b.HandleRequest(ctx, req); err != nil {
		t.Fatalf("role delete error: %v", err)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "role/ephemeral",
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
		Path:      "role/bad",
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
		Path:      "role/bad-ttl",
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
