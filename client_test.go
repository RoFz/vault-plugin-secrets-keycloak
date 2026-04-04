package secretsengine

import "testing"

func TestNewClient_NilConfig(t *testing.T) {
	_, err := newClient(nil)
	if err == nil {
		t.Fatal("expected error for nil config")
	}
}

func TestNewClient_MissingURL(t *testing.T) {
	_, err := newClient(&keycloakConfig{
		Realm:               "master",
		MasterAdminUsername: "admin",
		MasterAdminPassword: "secret",
	})
	if err == nil {
		t.Fatal("expected error for missing URL")
	}
}

func TestNewClient_EmptyRealmDefaultsToMaster(t *testing.T) {
	cfg := &keycloakConfig{
		URL:                 "https://keycloak.example.com",
		MasterAdminUsername: "admin",
		MasterAdminPassword: "secret",
	}
	c, err := newClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.realm != "master" {
		t.Errorf("expected realm 'master', got %q", c.realm)
	}
}

func TestNewClient_MissingUsername(t *testing.T) {
	_, err := newClient(&keycloakConfig{
		URL:                 "https://keycloak.example.com",
		Realm:               "master",
		MasterAdminPassword: "secret",
	})
	if err == nil {
		t.Fatal("expected error for missing username")
	}
}

func TestNewClient_MissingPassword(t *testing.T) {
	_, err := newClient(&keycloakConfig{
		URL:                 "https://keycloak.example.com",
		Realm:               "master",
		MasterAdminUsername: "admin",
	})
	if err == nil {
		t.Fatal("expected error for missing password")
	}
}

func TestNewClient_DefaultClientID(t *testing.T) {
	cfg := &keycloakConfig{
		URL:                 "https://keycloak.example.com",
		Realm:               "master",
		MasterAdminUsername: "admin",
		MasterAdminPassword: "secret",
	}
	c, err := newClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.clientID != "admin-cli" {
		t.Errorf("expected default client_id 'admin-cli', got %q", c.clientID)
	}
}

func TestNewClient_TargetRealmDefaultsToRealm(t *testing.T) {
	cfg := &keycloakConfig{
		URL:                 "https://keycloak.example.com",
		Realm:               "master",
		MasterAdminUsername: "admin",
		MasterAdminPassword: "secret",
	}
	c, err := newClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.targetRealm != "master" {
		t.Errorf("expected target_realm 'master', got %q", c.targetRealm)
	}
}

func TestNewClient_ExplicitTargetRealm(t *testing.T) {
	cfg := &keycloakConfig{
		URL:                 "https://keycloak.example.com",
		Realm:               "master",
		TargetRealm:         "myrealm",
		MasterAdminUsername: "admin",
		MasterAdminPassword: "secret",
	}
	c, err := newClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.targetRealm != "myrealm" {
		t.Errorf("expected target_realm 'myrealm', got %q", c.targetRealm)
	}
}

func TestNewClient_TrailingSlashStripped(t *testing.T) {
	cfg := &keycloakConfig{
		URL:                 "https://keycloak.example.com/",
		Realm:               "master",
		MasterAdminUsername: "admin",
		MasterAdminPassword: "secret",
	}
	c, err := newClient(cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.baseURL != "https://keycloak.example.com" {
		t.Errorf("expected trailing slash stripped, got %q", c.baseURL)
	}
}
