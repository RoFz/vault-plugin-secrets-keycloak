package secretsengine

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestWriteKVSecret_CreatesWhenMissing covers the 404 -> create fallback: when
// the KV v2 secret does not exist yet, the PATCH returns 404 and writeKVSecret
// must fall back to a full write (create) rather than failing.
func TestWriteKVSecret_CreatesWhenMissing(t *testing.T) {
	var patched, written bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPatch:
			patched = true
			http.Error(w, `{"errors":["not found"]}`, http.StatusNotFound)
		default: // PUT (create)
			written = true
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"data":{"version":1}}`)
		}
	}))
	defer srv.Close()

	warning, err := writeKVSecret(context.Background(), kvSyncRequest{
		vaultAddr:   srv.URL,
		callerToken: "kv-token",
		mountPath:   "secret",
		secretPath:  "keycloak/app",
		key:         "password",
		password:    "pw-value",
	})
	if err != nil {
		t.Fatalf("create fallback must succeed; err=%v warning=%q", err, warning)
	}
	if warning != "" {
		t.Errorf("expected no warning on success, got %q", warning)
	}
	if !patched || !written {
		t.Errorf("expected a PATCH (404) then a create PUT; patched=%v written=%v", patched, written)
	}
}
