package secretsengine

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

// fakeKeycloakClient is an in-memory implementation of keycloakClientIface for tests.
type fakeKeycloakClient struct {
	resetCalls []fakeResetCall
	resetErr   error
}

type fakeResetCall struct {
	username string
	password string
}

func (f *fakeKeycloakClient) ResetPassword(_ context.Context, username, password string) error {
	f.resetCalls = append(f.resetCalls, fakeResetCall{username, password})
	return f.resetErr
}

func (f *fakeKeycloakClient) ListUsers(_ context.Context) ([]keycloakUserInfo, error) {
	return nil, nil
}

func (f *fakeKeycloakClient) GetUser(_ context.Context, username string) (*keycloakUserInfo, error) {
	return &keycloakUserInfo{Username: username}, nil
}

// newTestBackendWithFakeClient returns a backend with a fake Keycloak client
// pre-injected so tests don't need a real Keycloak instance or stored config.
func newTestBackendWithFakeClient(t *testing.T) (*keycloakBackend, logical.Storage, *fakeKeycloakClient) {
	t.Helper()
	b, storage := newTestBackend(t)
	fake := &fakeKeycloakClient{}
	b.client = fake
	return b, storage, fake
}

// writeStaticRole creates a non-ephemeral role via the API (triggers initial rotation).
func writeStaticRole(t *testing.T, b *keycloakBackend, storage logical.Storage, roleName, username string) {
	t.Helper()
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/" + roleName,
		Storage:   storage,
		Data: map[string]interface{}{
			"keycloak_username": username,
			"rotation_period":   1800,
		},
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("static role write error: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("static role write returned error: %s", resp.Error())
	}
}

// --- Static role creation tests ---

func TestValidStaticRoleCreation(t *testing.T) {
	b, storage, fake := newTestBackendWithFakeClient(t)

	writeStaticRole(t, b, storage, "bob", "bob-kc")

	// Initial rotation must have been called exactly once.
	if len(fake.resetCalls) != 1 {
		t.Fatalf("expected 1 ResetPassword call, got %d", len(fake.resetCalls))
	}
	if fake.resetCalls[0].username != "bob-kc" {
		t.Errorf("expected ResetPassword for 'bob-kc', got %q", fake.resetCalls[0].username)
	}

	// Credential must be stored.
	cred, err := getStaticCred(context.Background(), storage, "bob")
	if err != nil {
		t.Fatalf("getStaticCred error: %v", err)
	}
	if cred == nil {
		t.Fatal("expected stored static credential after role creation, got nil")
	}
	if cred.Password == "" {
		t.Error("stored password must not be empty")
	}
}

func TestStaticRoleCreationInitialRotationFailure(t *testing.T) {
	b, storage, fake := newTestBackendWithFakeClient(t)
	fake.resetErr = fmt.Errorf("keycloak unavailable")

	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/bob",
		Storage:   storage,
		Data: map[string]interface{}{
			"keycloak_username": "bob-kc",
			"rotation_period":   1800,
		},
	}
	_, err := b.HandleRequest(context.Background(), req)
	if err == nil {
		t.Fatal("expected error when initial rotation fails")
	}

	// Role must not persist after a failed initial rotation.
	role, err := b.getRole(context.Background(), storage, "bob")
	if err != nil {
		t.Fatalf("getRole error: %v", err)
	}
	if role != nil {
		t.Error("role must not be stored when initial rotation fails")
	}
}

// --- static-creds/<name> read tests ---

func TestStaticCredsReadAfterCreation(t *testing.T) {
	b, storage, _ := newTestBackendWithFakeClient(t)

	writeStaticRole(t, b, storage, "alice", "alice-kc")

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "static-creds/alice",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("static-creds read error: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("expected successful response, got: %v", resp)
	}
	if resp.Data["username"] != "alice-kc" {
		t.Errorf("expected username 'alice-kc', got %v", resp.Data["username"])
	}
	if resp.Data["password"] == "" {
		t.Error("expected non-empty password")
	}
	if resp.Data["rotation_period"] != float64(1800) {
		t.Errorf("expected rotation_period=1800, got %v", resp.Data["rotation_period"])
	}
}

func TestStaticCredsReadEphemeralRole(t *testing.T) {
	b, storage := newTestBackend(t)
	ctx := context.Background()

	// Create an ephemeral role.
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/ephem",
		Storage:   storage,
		Data: map[string]interface{}{
			"keycloak_username": "someuser",
			"ephemeral":         true,
			"ttl":               3600,
			"max_ttl":           86400,
		},
	}
	if _, err := b.HandleRequest(ctx, req); err != nil {
		t.Fatalf("role write error: %v", err)
	}

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "static-creds/ephem",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("static-creds read error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response when reading static-creds for an ephemeral role")
	}
}

func TestCredsReadStaticRole(t *testing.T) {
	b, storage, _ := newTestBackendWithFakeClient(t)

	writeStaticRole(t, b, storage, "carol", "carol-kc")

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/carol",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("creds read error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response when reading creds/<name> for a static role")
	}
}

func TestStaticCredsNoCredStored(t *testing.T) {
	b, storage := newTestBackend(t)
	ctx := context.Background()

	// Write a non-ephemeral role directly to storage, bypassing the API so no
	// initial rotation is triggered and no static credential is stored.
	if err := b.setRole(ctx, storage, "ghost", &keycloakRoleEntry{
		KeycloakUsername: "ghost-kc",
		Ephemeral:        false,
		RotationPeriod:   30 * time.Minute,
	}); err != nil {
		t.Fatalf("setRole error: %v", err)
	}

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "static-creds/ghost",
		Storage:   storage,
	}
	resp, err := b.HandleRequest(ctx, req)
	if err != nil {
		t.Fatalf("static-creds read error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatal("expected error response when no credential is stored yet")
	}
}

// --- Periodic rotation tests ---

func TestPeriodicFuncRotatesOverdueRole(t *testing.T) {
	b, storage, fake := newTestBackendWithFakeClient(t)
	ctx := context.Background()

	// Write the role directly and pre-populate a stale credential.
	if err := b.setRole(ctx, storage, "dave", &keycloakRoleEntry{
		KeycloakUsername: "dave-kc",
		Ephemeral:        false,
		RotationPeriod:   30 * time.Minute,
	}); err != nil {
		t.Fatalf("setRole error: %v", err)
	}
	if err := setStaticCred(ctx, storage, "dave", &staticCredEntry{
		Password:     "old-password",
		LastRotation: time.Now().Add(-2 * time.Hour), // overdue
	}); err != nil {
		t.Fatalf("setStaticCred error: %v", err)
	}

	if err := b.periodicFunc(ctx, &logical.Request{Storage: storage}); err != nil {
		t.Fatalf("periodicFunc error: %v", err)
	}

	if len(fake.resetCalls) != 1 {
		t.Fatalf("expected 1 ResetPassword call, got %d", len(fake.resetCalls))
	}
	if fake.resetCalls[0].username != "dave-kc" {
		t.Errorf("expected rotation for 'dave-kc', got %q", fake.resetCalls[0].username)
	}

	// Stored credential must be updated with a new password.
	cred, err := getStaticCred(ctx, storage, "dave")
	if err != nil {
		t.Fatalf("getStaticCred error: %v", err)
	}
	if cred.Password == "old-password" {
		t.Error("expected password to be updated after rotation")
	}
}

func TestPeriodicFuncSkipsNonOverdueRole(t *testing.T) {
	b, storage, fake := newTestBackendWithFakeClient(t)
	ctx := context.Background()

	if err := b.setRole(ctx, storage, "eve", &keycloakRoleEntry{
		KeycloakUsername: "eve-kc",
		Ephemeral:        false,
		RotationPeriod:   30 * time.Minute,
	}); err != nil {
		t.Fatalf("setRole error: %v", err)
	}
	if err := setStaticCred(ctx, storage, "eve", &staticCredEntry{
		Password:     "fresh-password",
		LastRotation: time.Now().Add(-5 * time.Minute), // recently rotated
	}); err != nil {
		t.Fatalf("setStaticCred error: %v", err)
	}

	if err := b.periodicFunc(ctx, &logical.Request{Storage: storage}); err != nil {
		t.Fatalf("periodicFunc error: %v", err)
	}

	if len(fake.resetCalls) != 0 {
		t.Errorf("expected 0 ResetPassword calls for a non-overdue role, got %d", len(fake.resetCalls))
	}
}

func TestPeriodicFuncSkipsEphemeralRoles(t *testing.T) {
	b, storage, fake := newTestBackendWithFakeClient(t)
	ctx := context.Background()

	if err := b.setRole(ctx, storage, "frank", &keycloakRoleEntry{
		KeycloakUsername: "frank-kc",
		Ephemeral:        true,
		TTL:              time.Hour,
		MaxTTL:           24 * time.Hour,
	}); err != nil {
		t.Fatalf("setRole error: %v", err)
	}

	if err := b.periodicFunc(ctx, &logical.Request{Storage: storage}); err != nil {
		t.Fatalf("periodicFunc error: %v", err)
	}

	if len(fake.resetCalls) != 0 {
		t.Errorf("expected 0 ResetPassword calls for ephemeral role, got %d", len(fake.resetCalls))
	}
}
