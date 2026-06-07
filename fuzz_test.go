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
