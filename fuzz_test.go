package secretsengine

import (
	"encoding/json"
	"testing"
	"time"
)

// Fuzz scope: the plugin parses untrusted input (Keycloak API responses and Vault
// storage entries) only via the standard library encoding/json into typed structs
// with length-guarded access, so there is no hand-rolled parser for a fuzzer to
// break; these targets only assert panic-safety of decoding and response formatting.
// Add dedicated targets and a scheduled fuzz workflow only if code is later
// introduced that parses untrusted bytes by hand.

// FuzzRoleEntryJSONRoundtrip exercises the JSON decode -> toResponseData path.
// Corrupted storage bytes reaching DecodeJSON must never cause a panic.
func FuzzRoleEntryJSONRoundtrip(f *testing.F) {
	f.Add(`{"keycloak_username":"user@example.com","ttl":3600000000000,"max_ttl":86400000000000,"kv_password_key":"secret/path"}`)
	f.Add(`{}`)
	f.Add(`{"keycloak_username":"","ttl":0,"max_ttl":0,"kv_password_key":""}`)
	f.Add(`{"keycloak_username":null}`)
	f.Fuzz(func(t *testing.T, raw string) {
		var role keycloakRoleEntry
		if err := json.Unmarshal([]byte(raw), &role); err != nil {
			return
		}
		_ = role.toResponseData()
	})
}

// FuzzRoleEntryToResponseData verifies toResponseData never panics regardless
// of what field values are stored in a role entry.
func FuzzRoleEntryToResponseData(f *testing.F) {
	f.Add("user@example.com", 3600, 86400, "secret/path")
	f.Add("", 0, 0, "")
	f.Add("user with spaces", -1, -1, "/a/b/c")
	f.Fuzz(func(t *testing.T, username string, ttlSec, maxTTLSec int, kvKey string) {
		role := &keycloakRoleEntry{
			KeycloakUsername: username,
			TTL:              time.Duration(ttlSec) * time.Second,
			MaxTTL:           time.Duration(maxTTLSec) * time.Second,
			KVPasswordKey:    kvKey,
		}
		data := role.toResponseData()
		if data == nil {
			t.Fatal("toResponseData must not return nil")
		}
	})
}

// FuzzNormalizeRoleInvariant guards the rotation-storm invariant over the
// whole input space: any JSON that decodes into a role entry must, after
// normalizeRole, be ephemeral whenever rotation_period is zero. A violation
// of this property is exactly the v0.2.x-upgrade bug class where a role with
// no rotation_period was treated as static and rotated on every periodic
// tick (see SECURITY_IMPROVEMENTS.md step 2).
func FuzzNormalizeRoleInvariant(f *testing.F) {
	// v0.2.0-shaped legacy roles (no ephemeral field, with and without ttl).
	f.Add(`{"keycloak_username":"svc","ttl":0,"max_ttl":0,"kv_password_key":""}`)
	f.Add(`{"keycloak_username":"svc","ttl":3600000000000,"max_ttl":86400000000000}`)
	// v0.3.0 shapes.
	f.Add(`{"keycloak_username":"svc","ephemeral":true,"ttl":3600000000000}`)
	f.Add(`{"keycloak_username":"svc","ephemeral":false,"rotation_period":1800000000000}`)
	// Corrupted/hand-edited shapes.
	f.Add(`{"ephemeral":false,"rotation_period":-1}`)
	f.Add(`{"rotation_period":0}`)
	f.Fuzz(func(t *testing.T, raw string) {
		var role keycloakRoleEntry
		if err := json.Unmarshal([]byte(raw), &role); err != nil {
			return
		}
		normalizeRole(&role)
		if role.RotationPeriod == 0 && !role.Ephemeral {
			t.Fatalf("invariant violated: zero rotation_period must imply ephemeral (role=%+v)", role)
		}
		_ = role.toResponseData()
	})
}

// FuzzStaticCredEntryDecode asserts panic-safety of the static credential
// storage decode and of the response formatting applied to it (RFC 3339
// rendering and next_rotation arithmetic), including extreme timestamps.
func FuzzStaticCredEntryDecode(f *testing.F) {
	f.Add(`{"password":"p","last_rotation":"2026-06-11T10:00:00Z","kv_synced":true}`)
	f.Add(`{}`)
	f.Add(`{"password":"","last_rotation":"0001-01-01T00:00:00Z","kv_synced":false}`)
	f.Add(`{"last_rotation":"9999-12-31T23:59:59Z"}`)
	f.Add(`{"password":null,"last_rotation":null}`)
	f.Fuzz(func(t *testing.T, raw string) {
		var cred staticCredEntry
		if err := json.Unmarshal([]byte(raw), &cred); err != nil {
			return
		}
		// The formatting performed by pathStaticCredsRead must never panic.
		_ = cred.LastRotation.Format(time.RFC3339)
		for _, period := range []time.Duration{0, 30 * time.Minute, -time.Hour, 1<<62 - 1} {
			_ = cred.LastRotation.Add(period).Format(time.RFC3339)
			_ = time.Since(cred.LastRotation) > 2*period
		}
	})
}
