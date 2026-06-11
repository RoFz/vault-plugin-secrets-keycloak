package secretsengine

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

// fakeKeycloakClient is an in-memory implementation of keycloakClientIface for
// tests. The mutex makes it safe for concurrent rotation tests; sequential
// tests may read resetCalls directly once all calls have completed.
type fakeKeycloakClient struct {
	mu         sync.Mutex
	resetCalls []fakeResetCall
	resetErr   error
}

type fakeResetCall struct {
	username string
	password string
}

func (f *fakeKeycloakClient) ResetPassword(_ context.Context, username, password string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resetCalls = append(f.resetCalls, fakeResetCall{username, password})
	return f.resetErr
}

// lastResetPassword returns the password of the most recent ResetPassword call.
func (f *fakeKeycloakClient) lastResetPassword(t *testing.T) string {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.resetCalls) == 0 {
		t.Fatal("no ResetPassword calls recorded")
	}
	return f.resetCalls[len(f.resetCalls)-1].password
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

	// Two rotations: creation, and the fresh rotation on conversion back to
	// static (conversion to ephemeral leaves the password untouched).
	if len(fake.resetCalls) != 2 {
		t.Fatalf("expected creation + reconversion rotations, got %d calls", len(fake.resetCalls))
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

// --- Rotation serialization tests (v0.3.0) ---

func TestConcurrentRotationsKeepStorageConsistent(t *testing.T) {
	b, storage, fake := newTestBackendWithFakeClient(t)
	ctx := context.Background()

	writeStaticRole(t, b, storage, "race", "race-kc")
	role, err := b.getRole(ctx, storage, "race")
	if err != nil || role == nil {
		t.Fatalf("getRole error: %v", err)
	}

	// Interleave manual user rotations with direct static rotations. Every
	// reset+store pair must be atomic: when the dust settles, the stored
	// password must be the one set by the LAST ResetPassword call.
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, _ = b.HandleRequest(ctx, &logical.Request{
				Operation: logical.UpdateOperation,
				Path:      "users/race-kc/rotate",
				Storage:   storage,
			})
		}()
		go func() {
			defer wg.Done()
			_ = b.rotateStaticCred(ctx, storage, "race", role)
		}()
	}
	wg.Wait()

	cred, err := getStaticCred(ctx, storage, "race")
	if err != nil || cred == nil {
		t.Fatalf("getStaticCred error: %v", err)
	}
	if got, want := cred.Password, fake.lastResetPassword(t); got != want {
		t.Error("stored password diverged from the last password set in Keycloak")
	}
}

// --- Delete and mode-switch hygiene tests (v0.3.0) ---

func TestStaticRoleDeleteLeavesPasswordWorking(t *testing.T) {
	b, storage, fake := newTestBackendWithFakeClient(t)
	ctx := context.Background()

	writeStaticRole(t, b, storage, "del", "del-kc")

	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/del",
		Storage:   storage,
	}); err != nil {
		t.Fatalf("role delete error: %v", err)
	}

	// Continuity-first: only the creation rotation, no discard on delete.
	if len(fake.resetCalls) != 1 {
		t.Fatalf("delete must not rotate the password, got %d calls", len(fake.resetCalls))
	}

	role, err := b.getRole(ctx, storage, "del")
	if err != nil || role != nil {
		t.Errorf("role must be deleted, got role=%v err=%v", role, err)
	}
	cred, err := getStaticCred(ctx, storage, "del")
	if err != nil || cred != nil {
		t.Errorf("static credential must be deleted, got cred=%v err=%v", cred, err)
	}
}

func TestStaticRoleDeleteSucceedsWhenKeycloakDown(t *testing.T) {
	b, storage, fake := newTestBackendWithFakeClient(t)
	ctx := context.Background()

	writeStaticRole(t, b, storage, "del2", "del2-kc")
	fake.resetErr = fmt.Errorf("keycloak unavailable")

	// Delete touches Vault state only, so Keycloak availability is irrelevant.
	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/del2",
		Storage:   storage,
	}); err != nil {
		t.Fatalf("delete must succeed while Keycloak is down, got: %v", err)
	}

	role, err := b.getRole(ctx, storage, "del2")
	if err != nil || role != nil {
		t.Errorf("role must be deleted, got role=%v err=%v", role, err)
	}
}

func TestEphemeralRoleDeleteDoesNotDiscard(t *testing.T) {
	b, storage, fake := newTestBackendWithFakeClient(t)
	ctx := context.Background()

	if resp, err := updateRole(t, b, storage, "edel", map[string]interface{}{
		"keycloak_username": "edel-kc",
		"ephemeral":         true,
		"ttl":               3600,
		"max_ttl":           86400,
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("ephemeral role write failed: err=%v resp=%v", err, resp)
	}

	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/edel",
		Storage:   storage,
	}); err != nil {
		t.Fatalf("role delete error: %v", err)
	}
	if len(fake.resetCalls) != 0 {
		t.Errorf("ephemeral role delete must not rotate, got %d calls", len(fake.resetCalls))
	}
}

func TestConversionToEphemeralCleansStorageOnly(t *testing.T) {
	b, storage, fake := newTestBackendWithFakeClient(t)
	ctx := context.Background()

	writeStaticRole(t, b, storage, "conv", "conv-kc")
	if resp, err := updateRole(t, b, storage, "conv", map[string]interface{}{
		"ephemeral": true,
		"ttl":       3600,
		"max_ttl":   86400,
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("conversion to ephemeral failed: err=%v resp=%v", err, resp)
	}

	// Continuity-first: only the creation rotation, no discard on conversion;
	// the live password keeps working while Vault stops managing it.
	if len(fake.resetCalls) != 1 {
		t.Fatalf("conversion must not rotate the password, got %d calls", len(fake.resetCalls))
	}
	cred, err := getStaticCred(ctx, storage, "conv")
	if err != nil || cred != nil {
		t.Errorf("static credential must be removed on conversion, got cred=%v err=%v", cred, err)
	}

	// Stale rotation_period must be zeroed on the persisted entry.
	role, err := b.getRole(ctx, storage, "conv")
	if err != nil || role == nil {
		t.Fatalf("getRole error: %v", err)
	}
	if role.RotationPeriod != 0 {
		t.Errorf("rotation_period must be zeroed after conversion, got %v", role.RotationPeriod)
	}
}

func TestConversionToStaticZeroesLeaseFields(t *testing.T) {
	b, storage, _ := newTestBackendWithFakeClient(t)
	ctx := context.Background()

	if resp, err := updateRole(t, b, storage, "z", map[string]interface{}{
		"keycloak_username": "z-kc",
		"ephemeral":         true,
		"ttl":               3600,
		"max_ttl":           86400,
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("ephemeral role write failed: err=%v resp=%v", err, resp)
	}
	if resp, err := updateRole(t, b, storage, "z", map[string]interface{}{
		"ephemeral":       false,
		"rotation_period": 1800,
	}); err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("conversion to static failed: err=%v resp=%v", err, resp)
	}

	role, err := b.getRole(ctx, storage, "z")
	if err != nil || role == nil {
		t.Fatalf("getRole error: %v", err)
	}
	if role.TTL != 0 || role.MaxTTL != 0 {
		t.Errorf("ttl/max_ttl must be zeroed after conversion to static, got ttl=%v max_ttl=%v", role.TTL, role.MaxTTL)
	}
}

// --- Scheduled-vs-manual rotation deferral tests (v0.3.0) ---

func TestRotateIfDueSkipsFreshCredential(t *testing.T) {
	b, storage, fake := newTestBackendWithFakeClient(t)
	ctx := context.Background()

	role := &keycloakRoleEntry{
		KeycloakUsername: "due-kc",
		RotationPeriod:   30 * time.Minute,
	}
	if err := b.setRole(ctx, storage, "due", role); err != nil {
		t.Fatalf("setRole error: %v", err)
	}

	// A manual rotation just happened (timestamp is fresh): the scheduled
	// rotation must detect it under the lock and skip.
	if err := setStaticCred(ctx, storage, "due", &staticCredEntry{
		Password:     "fresh",
		LastRotation: time.Now().Add(-1 * time.Minute),
	}); err != nil {
		t.Fatalf("setStaticCred error: %v", err)
	}
	if err := b.rotateStaticCredIfDue(ctx, storage, "due", role); err != nil {
		t.Fatalf("rotateStaticCredIfDue error: %v", err)
	}
	if len(fake.resetCalls) != 0 {
		t.Fatalf("scheduled rotation must skip a freshly rotated credential, got %d calls", len(fake.resetCalls))
	}

	// Overdue credential: the same path must rotate.
	if err := setStaticCred(ctx, storage, "due", &staticCredEntry{
		Password:     "stale",
		LastRotation: time.Now().Add(-2 * time.Hour),
	}); err != nil {
		t.Fatalf("setStaticCred error: %v", err)
	}
	if err := b.rotateStaticCredIfDue(ctx, storage, "due", role); err != nil {
		t.Fatalf("rotateStaticCredIfDue error: %v", err)
	}
	if len(fake.resetCalls) != 1 {
		t.Fatalf("overdue credential must rotate, got %d calls", len(fake.resetCalls))
	}
}

// --- Non-blocking sweep and failure backoff tests (v0.3.0) ---

func TestRotateIfDueSkipsWhenLockBusy(t *testing.T) {
	b, storage, fake := newTestBackendWithFakeClient(t)
	ctx := context.Background()

	role := &keycloakRoleEntry{
		KeycloakUsername: "busy-kc",
		RotationPeriod:   30 * time.Minute,
	}
	if err := b.setRole(ctx, storage, "busy", role); err != nil {
		t.Fatalf("setRole error: %v", err)
	}

	// Simulate another rotation in flight.
	b.rotationLock.Lock()
	err := b.rotateStaticCredIfDue(ctx, storage, "busy", role)
	b.rotationLock.Unlock()

	if !errors.Is(err, errRotationInProgress) {
		t.Fatalf("expected errRotationInProgress, got %v", err)
	}
	if len(fake.resetCalls) != 0 {
		t.Fatalf("no rotation must run while the lock is busy, got %d calls", len(fake.resetCalls))
	}
}

func TestPeriodicFuncBacksOffAfterFailures(t *testing.T) {
	b, storage, fake := newTestBackendWithFakeClient(t)
	ctx := context.Background()

	if err := b.setRole(ctx, storage, "flaky", &keycloakRoleEntry{
		KeycloakUsername: "flaky-kc",
		RotationPeriod:   30 * time.Minute,
	}); err != nil {
		t.Fatalf("setRole error: %v", err)
	}
	if err := setStaticCred(ctx, storage, "flaky", &staticCredEntry{
		Password:     "old",
		LastRotation: time.Now().Add(-2 * time.Hour), // overdue
	}); err != nil {
		t.Fatalf("setStaticCred error: %v", err)
	}
	fake.resetErr = fmt.Errorf("keycloak unavailable")

	// First sweep: one attempt, which fails and arms the backoff.
	if err := b.periodicFunc(ctx, &logical.Request{Storage: storage}); err != nil {
		t.Fatalf("periodicFunc error: %v", err)
	}
	if len(fake.resetCalls) != 1 {
		t.Fatalf("expected 1 attempt on the first sweep, got %d", len(fake.resetCalls))
	}

	// Immediate next sweeps: inside the 1-minute backoff window, no attempts.
	for i := 0; i < 3; i++ {
		if err := b.periodicFunc(ctx, &logical.Request{Storage: storage}); err != nil {
			t.Fatalf("periodicFunc error: %v", err)
		}
	}
	if len(fake.resetCalls) != 1 {
		t.Fatalf("sweeps within the backoff window must not attempt, got %d calls", len(fake.resetCalls))
	}

	// Backoff growth: 3 consecutive failures wait 4 minutes, capped at 16.
	b.backoffMu.Lock()
	b.rotationBackoff["flaky"].failures = 3
	b.backoffMu.Unlock()
	if got := b.rotationBackoffRemaining("flaky"); got <= 3*time.Minute || got > 4*time.Minute {
		t.Errorf("expected ~4m remaining after 3 failures, got %v", got)
	}
	b.backoffMu.Lock()
	b.rotationBackoff["flaky"].failures = 10
	b.backoffMu.Unlock()
	if got := b.rotationBackoffRemaining("flaky"); got > maxRotationBackoff {
		t.Errorf("backoff must be capped at %v, got %v", maxRotationBackoff, got)
	}

	// Keycloak recovers and the backoff window elapses: next sweep rotates
	// once and clears the failure history.
	fake.resetErr = nil
	b.backoffMu.Lock()
	b.rotationBackoff["flaky"].lastAttempt = time.Now().Add(-time.Hour)
	b.backoffMu.Unlock()
	if err := b.periodicFunc(ctx, &logical.Request{Storage: storage}); err != nil {
		t.Fatalf("periodicFunc error: %v", err)
	}
	if len(fake.resetCalls) != 2 {
		t.Fatalf("expected exactly one catch-up rotation after recovery, got %d calls", len(fake.resetCalls))
	}
	if b.rotationBackoffRemaining("flaky") != 0 {
		t.Error("backoff must be cleared after a successful rotation")
	}
	b.backoffMu.Lock()
	_, lingering := b.rotationBackoff["flaky"]
	b.backoffMu.Unlock()
	if lingering {
		t.Error("backoff state must be removed after success")
	}
}

func TestPeriodicFuncClearsBackoffWhenFresh(t *testing.T) {
	b, storage, fake := newTestBackendWithFakeClient(t)
	ctx := context.Background()

	if err := b.setRole(ctx, storage, "healed", &keycloakRoleEntry{
		KeycloakUsername: "healed-kc",
		RotationPeriod:   30 * time.Minute,
	}); err != nil {
		t.Fatalf("setRole error: %v", err)
	}
	// Failure history from a past outage, but the credential is fresh now
	// (e.g. a manual rotation succeeded meanwhile).
	b.recordRotationFailure("healed")
	if err := setStaticCred(ctx, storage, "healed", &staticCredEntry{
		Password:     "fresh",
		LastRotation: time.Now().Add(-1 * time.Minute),
	}); err != nil {
		t.Fatalf("setStaticCred error: %v", err)
	}

	if err := b.periodicFunc(ctx, &logical.Request{Storage: storage}); err != nil {
		t.Fatalf("periodicFunc error: %v", err)
	}
	if len(fake.resetCalls) != 0 {
		t.Fatalf("fresh credential must not rotate, got %d calls", len(fake.resetCalls))
	}
	b.backoffMu.Lock()
	_, lingering := b.rotationBackoff["healed"]
	b.backoffMu.Unlock()
	if lingering {
		t.Error("stale failure history must be cleared when the role is no longer overdue")
	}
}
