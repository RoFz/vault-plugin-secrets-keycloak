package secretsengine

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// testAdminPassword is the master admin password used across tests. It is a
// recognizable sentinel so leak assertions can check it never appears in any
// response, warning, or error returned to a caller.
const testAdminPassword = "super-secret-admin-pw"

// fakeKCUser is the default single-user list the fake returns for any users
// query (id uid-1, username alice).
const fakeKCUser = `[{"id":"uid-1","username":"alice","enabled":true,"email":"alice@test.local","firstName":"Al","lastName":"Ice"}]`

// fakeKC is a configurable, recording stand-in for the Keycloak Admin REST API.
// The zero value serves success responses: a token, one user (alice/uid-1), and
// a 204 on reset-password. The *Status fields force error responses for
// negative tests, and the counters let tests assert behaviour, for example that
// revoking a lease actually issues a password reset.
type fakeKC struct {
	t  *testing.T
	mu sync.Mutex

	tokenCount int
	resetCount int

	tokenStatus int    // 0 => 200 with a valid token
	usersStatus int    // 0 => 200 with usersBody
	usersBody   string // "" => fakeKCUser
	resetStatus int    // 0 => 204 No Content
}

func (f *fakeKC) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()

	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/protocol/openid-connect/token"):
		f.tokenCount++
		if f.tokenStatus != 0 {
			http.Error(w, `{"error":"invalid_grant"}`, f.tokenStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"access_token":"fake-admin-token"}`)

	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/users"):
		if f.usersStatus != 0 {
			http.Error(w, `{"error":"forbidden"}`, f.usersStatus)
			return
		}
		body := f.usersBody
		if body == "" {
			body = fakeKCUser
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)

	case r.Method == http.MethodPut && strings.HasSuffix(r.URL.Path, "/reset-password"):
		f.resetCount++
		if f.resetStatus != 0 {
			http.Error(w, `{"error":"bad request"}`, f.resetStatus)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		f.t.Errorf("fake keycloak: unexpected request %s %s", r.Method, r.URL.Path)
		http.Error(w, "unexpected", http.StatusInternalServerError)
	}
}

// resets returns how many reset-password calls the fake has received.
func (f *fakeKC) resets() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.resetCount
}

// startFakeKC starts the fake server, registers cleanup, and returns its URL.
func startFakeKC(t *testing.T, f *fakeKC) string {
	t.Helper()
	f.t = t
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return srv.URL
}

// baseConfig returns a minimal valid /config payload pointing at url.
func baseConfig(url string) map[string]interface{} {
	return map[string]interface{}{
		"url":                   url,
		"realm":                 "master",
		"master_admin_username": "admin",
		"master_admin_password": testAdminPassword,
	}
}

// configureBackend writes data to the /config path on the backend.
func configureBackend(t *testing.T, b *keycloakBackend, storage logical.Storage, data map[string]interface{}) {
	t.Helper()
	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "config",
		Storage:   storage,
		Data:      data,
	}); err != nil {
		t.Fatalf("config write error: %v", err)
	}
}
