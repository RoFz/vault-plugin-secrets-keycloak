package secretsengine

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// keycloakUserInfo holds the fields returned by the Keycloak users API.
type keycloakUserInfo struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Enabled   bool   `json:"enabled"`
	Email     string `json:"email,omitempty"`
	FirstName string `json:"firstName,omitempty"`
	LastName  string `json:"lastName,omitempty"`
}

// keycloakClient holds configuration and an HTTP client for the Keycloak Admin REST API.
type keycloakClient struct {
	baseURL     string
	realm       string // auth realm (typically "master")
	targetRealm string // realm whose users are managed
	clientID    string
	username    string
	password    string
	httpClient  *http.Client
}

// newClient validates the config and returns a ready keycloakClient.
func newClient(config *keycloakConfig) (*keycloakClient, error) {
	if config == nil {
		return nil, fmt.Errorf("client configuration was nil")
	}
	if config.URL == "" {
		return nil, fmt.Errorf("keycloak URL is required")
	}
	if config.Realm == "" {
		return nil, fmt.Errorf("keycloak realm is required")
	}
	if config.ClientID == "" {
		config.ClientID = "admin-cli"
	}
	if config.Username == "" {
		return nil, fmt.Errorf("keycloak username is required")
	}
	if config.Password == "" {
		return nil, fmt.Errorf("keycloak password is required")
	}

	targetRealm := config.TargetRealm
	if targetRealm == "" {
		targetRealm = config.Realm
	}

	return &keycloakClient{
		baseURL:     strings.TrimRight(config.URL, "/"),
		realm:       config.Realm,
		targetRealm: targetRealm,
		clientID:    config.ClientID,
		username:    config.Username,
		password:    config.Password,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
	}, nil
}

// getAdminToken obtains a short-lived admin access token via the Resource Owner
// Password Credentials (ROPC) grant using the configured admin username and password.
func (c *keycloakClient) getAdminToken(ctx context.Context) (string, error) {
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.baseURL, c.realm)

	form := url.Values{}
	form.Set("grant_type", "password")
	form.Set("client_id", c.clientID)
	form.Set("username", c.username)
	form.Set("password", c.password)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("error building token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error fetching admin token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d fetching admin token: %s", resp.StatusCode, string(body))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("error parsing token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("empty access token in response")
	}

	return tokenResp.AccessToken, nil
}

// getUserIDByUsername returns the Keycloak internal UUID for the given username.
func (c *keycloakClient) getUserIDByUsername(ctx context.Context, token, username string) (string, error) {
	usersURL := fmt.Sprintf("%s/admin/realms/%s/users?username=%s&exact=true",
		c.baseURL, c.targetRealm, url.QueryEscape(username))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, usersURL, nil)
	if err != nil {
		return "", fmt.Errorf("error building users request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("error listing users: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("error reading users response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d listing users: %s", resp.StatusCode, string(body))
	}

	var users []struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}
	if err := json.Unmarshal(body, &users); err != nil {
		return "", fmt.Errorf("error parsing users response: %w", err)
	}
	if len(users) == 0 {
		return "", fmt.Errorf("user %q not found in realm %q", username, c.targetRealm)
	}

	return users[0].ID, nil
}

// ResetPassword sets a new password for the Keycloak user identified by username.
// It fetches a fresh admin token and resolves the user ID on every call.
func (c *keycloakClient) ResetPassword(ctx context.Context, username, password string) error {
	token, err := c.getAdminToken(ctx)
	if err != nil {
		return err
	}

	userID, err := c.getUserIDByUsername(ctx, token, username)
	if err != nil {
		return err
	}

	resetURL := fmt.Sprintf("%s/admin/realms/%s/users/%s/reset-password", c.baseURL, c.targetRealm, userID)

	payload, err := json.Marshal(map[string]interface{}{
		"type":      "password",
		"value":     password,
		"temporary": false,
	})
	if err != nil {
		return fmt.Errorf("error marshaling credential payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPut, resetURL, strings.NewReader(string(payload)))
	if err != nil {
		return fmt.Errorf("error building reset-password request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("error sending reset-password request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusNoContent {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("unexpected status %d resetting password for %q: %s", resp.StatusCode, username, string(body))
	}

	return nil
}

// ListUsers returns all users in the target realm (up to 500).
func (c *keycloakClient) ListUsers(ctx context.Context) ([]keycloakUserInfo, error) {
	token, err := c.getAdminToken(ctx)
	if err != nil {
		return nil, err
	}

	usersURL := fmt.Sprintf("%s/admin/realms/%s/users?max=500", c.baseURL, c.targetRealm)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, usersURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error building list-users request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error listing users: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading list-users response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d listing users: %s", resp.StatusCode, string(body))
	}

	var users []keycloakUserInfo
	if err := json.Unmarshal(body, &users); err != nil {
		return nil, fmt.Errorf("error parsing list-users response: %w", err)
	}
	return users, nil
}

// GetUser returns details for a specific user by exact username match, or nil if not found.
func (c *keycloakClient) GetUser(ctx context.Context, username string) (*keycloakUserInfo, error) {
	token, err := c.getAdminToken(ctx)
	if err != nil {
		return nil, err
	}

	usersURL := fmt.Sprintf("%s/admin/realms/%s/users?username=%s&exact=true",
		c.baseURL, c.targetRealm, url.QueryEscape(username))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, usersURL, nil)
	if err != nil {
		return nil, fmt.Errorf("error building get-user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error fetching user: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading get-user response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d fetching user %q: %s", resp.StatusCode, username, string(body))
	}

	var users []keycloakUserInfo
	if err := json.Unmarshal(body, &users); err != nil {
		return nil, fmt.Errorf("error parsing get-user response: %w", err)
	}
	if len(users) == 0 {
		return nil, nil
	}
	return &users[0], nil
}
