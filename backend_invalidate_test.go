package secretsengine

import (
	"context"
	"testing"
)

// TestInvalidate_ClearsCachedClientOnConfigChange guards against using stale
// admin credentials: when the config key is invalidated, the cached Keycloak
// client must be dropped so the next operation rebuilds it from current config.
func TestInvalidate_ClearsCachedClientOnConfigChange(t *testing.T) {
	url := startFakeKC(t, &fakeKC{})
	b, storage := newTestBackend(t)
	configureBackend(t, b, storage, baseConfig(url))

	// Populate the client cache.
	if _, err := b.getClient(context.Background(), storage); err != nil {
		t.Fatalf("getClient error: %v", err)
	}
	if b.client == nil {
		t.Fatal("expected a cached client after getClient")
	}

	// Invalidating a non-config key must leave the cache intact.
	b.invalidate(context.Background(), "roles/app")
	if b.client == nil {
		t.Error("invalidate of a non-config key must not clear the client")
	}

	// Invalidating the config key must drop the cached client.
	b.invalidate(context.Background(), "config")
	if b.client != nil {
		t.Error("invalidate of config must clear the cached client")
	}
}
