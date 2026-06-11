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

// --- Legacy (v0.1.x/v0.2.x) role compatibility tests ---

// putLegacyRole stores a raw role entry exactly as written by v0.1.x/v0.2.x
// (no ephemeral field, no rotation_period), bypassing the current write path.
func putLegacyRole(t *testing.T, storage logical.Storage, name, rawJSON string) {
	t.Helper()
	err := storage.Put(context.Background(), &logical.StorageEntry{
		Key:   "roles/" + name,
		Value: []byte(rawJSON),
	})
	if err != nil {
		t.Fatalf("failed to store legacy role: %v", err)
	}
}

func TestLegacyRoleShimClassifiesEphemeral(t *testing.T) {
	b, storage := newTestBackend(t)
	ctx := context.Background()

	// v0.2.x role created WITHOUT an explicit ttl: GetOk never stores schema
	// defaults, so TTL/MaxTTL are zero. Must still be classified ephemeral.
	putLegacyRole(t, storage, "legacy-nottl", `{"keycloak_username":"legacy1-kc","ttl":0,"max_ttl":0,"kv_password_key":""}`)
	// v0.2.x role with explicit ttl/max_ttl (stored as nanoseconds).
	putLegacyRole(t, storage, "legacy-ttl", `{"keycloak_username":"legacy2-kc","ttl":3600000000000,"max_ttl":86400000000000,"kv_password_key":""}`)

	for _, name := range []string{"legacy-nottl", "legacy-ttl"} {
		role, err := b.getRole(ctx, storage, name)
		if err != nil {
			t.Fatalf("getRole(%s) error: %v", name, err)
		}
		if role == nil {
			t.Fatalf("getRole(%s) returned nil", name)
		}
		if !role.Ephemeral {
			t.Errorf("legacy role %q must be classified ephemeral, got static", name)
		}
	}
}

func TestPeriodicFuncNeverRotatesLegacyRoles(t *testing.T) {
	b, storage, fake := newTestBackendWithFakeClient(t)
	ctx := context.Background()

	putLegacyRole(t, storage, "legacy-nottl", `{"keycloak_username":"legacy1-kc","ttl":0,"max_ttl":0,"kv_password_key":""}`)
	putLegacyRole(t, storage, "legacy-ttl", `{"keycloak_username":"legacy2-kc","ttl":3600000000000,"max_ttl":86400000000000,"kv_password_key":""}`)

	// Several ticks: a regression here would rotate on every single one.
	for i := 0; i < 3; i++ {
		if err := b.periodicFunc(ctx, &logical.Request{Storage: storage}); err != nil {
			t.Fatalf("periodicFunc error: %v", err)
		}
	}

	if len(fake.resetCalls) != 0 {
		t.Fatalf("legacy roles must never be autorotated, got %d ResetPassword calls", len(fake.resetCalls))
	}
	for _, name := range []string{"legacy-nottl", "legacy-ttl"} {
		cred, err := getStaticCred(ctx, storage, name)
		if err != nil {
			t.Fatalf("getStaticCred(%s) error: %v", name, err)
		}
		if cred != nil {
			t.Errorf("no static credential must be created for legacy role %q", name)
		}
	}
}

func TestLegacyRoleCredsReadStillWorks(t *testing.T) {
	b, storage, fake := newTestBackendWithFakeClient(t)

	putLegacyRole(t, storage, "legacy", `{"keycloak_username":"legacy-kc","ttl":0,"max_ttl":0,"kv_password_key":""}`)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "creds/legacy",
		Storage:   storage,
	})
	if err != nil {
		t.Fatalf("creds read error: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("legacy role must remain readable via creds/<role>, got: %v", resp)
	}
	if resp.Data["password"] == "" {
		t.Error("expected non-empty password for legacy role")
	}
	if len(fake.resetCalls) != 1 {
		t.Fatalf("expected exactly 1 ResetPassword call, got %d", len(fake.resetCalls))
	}
}

func TestPeriodicFuncSkipsNonPositiveRotationPeriod(t *testing.T) {
	b, storage, fake := newTestBackendWithFakeClient(t)
	ctx := context.Background()

	// A corrupted or hand-edited entry: explicitly static with a negative
	// period. The shim only reclassifies rotation_period==0, so this exercises
	// the periodicFunc defense-in-depth guard.
	putLegacyRole(t, storage, "corrupt", `{"keycloak_username":"corrupt-kc","ephemeral":false,"rotation_period":-1}`)

	if err := b.periodicFunc(ctx, &logical.Request{Storage: storage}); err != nil {
		t.Fatalf("periodicFunc error: %v", err)
	}
	if len(fake.resetCalls) != 0 {
		t.Fatalf("roles with non-positive rotation_period must never rotate, got %d calls", len(fake.resetCalls))
	}
}

// --- Role write: rotate-before-persist tests (v0.3.0) ---

// updateRole performs an UpdateOperation on roles/<name> and returns the response.
func updateRole(t *testing.T, b *keycloakBackend, storage logical.Storage, name string, data map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + name,
		Storage:   storage,
		Data:      data,
	})
}

func TestStaticRoleUpdateFailedRotationKeepsPriorRole(t *testing.T) {
	b, storage, fake := newTestBackendWithFakeClient(t)
	ctx := context.Background()

	writeStaticRole(t, b, storage, "bob", "bob-kc")
	credBefore, err := getStaticCred(ctx, storage, "bob")
	if err != nil || credBefore == nil {
		t.Fatalf("expected stored credential after creation, err=%v", err)
	}

	fake.resetErr = fmt.Errorf("keycloak unavailable")
	if _, err := updateRole(t, b, storage, "bob", map[string]interface{}{
		"keycloak_username": "bob2-kc",
	}); err == nil {
		t.Fatal("expected error when rotation for the new username fails")
	}

	role, err := b.getRole(ctx, storage, "bob")
	if err != nil || role == nil {
		t.Fatalf("prior role must survive a failed update, err=%v", err)
	}
	if role.KeycloakUsername != "bob-kc" {
		t.Errorf("prior role must keep its username, got %q", role.KeycloakUsername)
	}
	credAfter, err := getStaticCred(ctx, storage, "bob")
	if err != nil || credAfter == nil {
		t.Fatalf("prior credential must survive a failed update, err=%v", err)
	}
	if credAfter.Password != credBefore.Password {
		t.Error("stored credential must be unchanged after a failed update")
	}
}

func TestStaticRoleUsernameChangeRotatesImmediately(t *testing.T) {
	b, storage, fake := newTestBackendWithFakeClient(t)
	ctx := context.Background()

	writeStaticRole(t, b, storage, "carol", "carol-kc")
	if resp, err := updateRole(t, b, storage, "carol", map[string]interface{}{
		"keycloak_username": "carol2-kc",
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("username change failed: err=%v resp=%v", err, resp)
	}

	if len(fake.resetCalls) != 2 {
		t.Fatalf("expected a rotation for the new username, got %d calls", len(fake.resetCalls))
	}
	if fake.resetCalls[1].username != "carol2-kc" {
		t.Errorf("rotation must target the new username, got %q", fake.resetCalls[1].username)
	}

	cred, err := getStaticCred(ctx, storage, "carol")
	if err != nil || cred == nil {
		t.Fatalf("expected stored credential, err=%v", err)
	}
	if cred.Password != fake.resetCalls[1].password {
		t.Error("stored password must match the password set for the new username")
	}
}

func TestEphemeralConversionFailedRotationKeepsEphemeralRole(t *testing.T) {
	b, storage, fake := newTestBackendWithFakeClient(t)
	ctx := context.Background()

	if resp, err := updateRole(t, b, storage, "ephem", map[string]interface{}{
		"keycloak_username": "ephem-kc",
		"ephemeral":         true,
		"ttl":               3600,
		"max_ttl":           86400,
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("ephemeral role write failed: err=%v resp=%v", err, resp)
	}

	fake.resetErr = fmt.Errorf("keycloak unavailable")
	if _, err := updateRole(t, b, storage, "ephem", map[string]interface{}{
		"ephemeral":       false,
		"rotation_period": 1800,
	}); err == nil {
		t.Fatal("expected error when conversion-to-static rotation fails")
	}

	role, err := b.getRole(ctx, storage, "ephem")
	if err != nil || role == nil {
		t.Fatalf("role must survive a failed conversion, err=%v", err)
	}
	if !role.Ephemeral {
		t.Error("role must remain ephemeral after a failed conversion to static")
	}
}

func TestStaticEphemeralRoundTripRotates(t *testing.T) {
	b, storage, fake := newTestBackendWithFakeClient(t)
	ctx := context.Background()

	writeStaticRole(t, b, storage, "dave", "dave-kc")

	// Convert to ephemeral, then back to static. The credential stored during
	// the first static phase predates the round trip and must not be served
	// again: converting back must rotate.
	if resp, err := updateRole(t, b, storage, "dave", map[string]interface{}{
		"ephemeral": true,
		"ttl":       3600,
		"max_ttl":   86400,
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("conversion to ephemeral failed: err=%v resp=%v", err, resp)
	}
	if resp, err := updateRole(t, b, storage, "dave", map[string]interface{}{
		"ephemeral":       false,
		"rotation_period": 1800,
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("conversion back to static failed: err=%v resp=%v", err, resp)
	}

	if len(fake.resetCalls) != 2 {
		t.Fatalf("expected rotation on conversion back to static, got %d calls", len(fake.resetCalls))
	}
	cred, err := getStaticCred(ctx, storage, "dave")
	if err != nil || cred == nil {
		t.Fatalf("expected stored credential, err=%v", err)
	}
	if cred.Password != fake.resetCalls[1].password {
		t.Error("stored password must come from the post-conversion rotation")
	}
}

// --- Username exclusivity tests (v0.3.0) ---

func TestRoleWriteRejectsSharedUsername(t *testing.T) {
	b, storage, _ := newTestBackendWithFakeClient(t)

	writeStaticRole(t, b, storage, "s1", "shared-kc")
	if resp, err := updateRole(t, b, storage, "e0", map[string]interface{}{
		"keycloak_username": "shared-ephem-kc",
		"ephemeral":         true,
		"ttl":               3600,
		"max_ttl":           86400,
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("ephemeral role write failed: err=%v resp=%v", err, resp)
	}

	cases := []struct {
		name      string
		data      map[string]interface{}
		wantError bool
	}{
		{"static vs static", map[string]interface{}{
			"keycloak_username": "shared-kc",
			"rotation_period":   1800,
		}, true},
		{"ephemeral vs static", map[string]interface{}{
			"keycloak_username": "shared-kc",
			"ephemeral":         true,
			"ttl":               3600,
			"max_ttl":           86400,
		}, true},
		{"static vs ephemeral", map[string]interface{}{
			"keycloak_username": "shared-ephem-kc",
			"rotation_period":   1800,
		}, true},
		{"ephemeral vs ephemeral", map[string]interface{}{
			"keycloak_username": "shared-ephem-kc",
			"ephemeral":         true,
			"ttl":               3600,
			"max_ttl":           86400,
		}, false},
	}
	for i, tc := range cases {
		resp, err := updateRole(t, b, storage, fmt.Sprintf("candidate-%d", i), tc.data)
		if err != nil {
			t.Fatalf("%s: unexpected transport error: %v", tc.name, err)
		}
		gotError := resp != nil && resp.IsError()
		if gotError != tc.wantError {
			t.Errorf("%s: wantError=%v, got resp=%v", tc.name, tc.wantError, resp)
		}
	}

	// Rewriting a role with its own (unchanged) username must not conflict
	// with itself.
	if resp, err := updateRole(t, b, storage, "s1", map[string]interface{}{
		"rotation_period": 3600,
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Errorf("self-rewrite must be allowed: err=%v resp=%v", err, resp)
	}
}

func TestPeriodicFuncSkipsSharedUsernameRoles(t *testing.T) {
	b, storage, fake := newTestBackendWithFakeClient(t)
	ctx := context.Background()

	// Pre-existing storage that predates write-time exclusivity: two static
	// roles on one username, and a static role sharing with an ephemeral one.
	overdue := &staticCredEntry{Password: "old", LastRotation: time.Now().Add(-2 * time.Hour)}
	for _, name := range []string{"dup-a", "dup-b"} {
		if err := b.setRole(ctx, storage, name, &keycloakRoleEntry{
			KeycloakUsername: "dup-kc",
			RotationPeriod:   30 * time.Minute,
		}); err != nil {
			t.Fatalf("setRole error: %v", err)
		}
		if err := setStaticCred(ctx, storage, name, overdue); err != nil {
			t.Fatalf("setStaticCred error: %v", err)
		}
	}
	if err := b.setRole(ctx, storage, "mixed-static", &keycloakRoleEntry{
		KeycloakUsername: "mixed-kc",
		RotationPeriod:   30 * time.Minute,
	}); err != nil {
		t.Fatalf("setRole error: %v", err)
	}
	if err := setStaticCred(ctx, storage, "mixed-static", overdue); err != nil {
		t.Fatalf("setStaticCred error: %v", err)
	}
	if err := b.setRole(ctx, storage, "mixed-ephem", &keycloakRoleEntry{
		KeycloakUsername: "mixed-kc",
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
		t.Fatalf("shared-username roles must never be autorotated, got %d calls", len(fake.resetCalls))
	}
}
