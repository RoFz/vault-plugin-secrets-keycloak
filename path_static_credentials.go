package secretsengine

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/logical"
)

// staticCredEntry holds the autorotated password for a static (non-ephemeral) role.
type staticCredEntry struct {
	Password     string    `json:"password"`
	LastRotation time.Time `json:"last_rotation"`
	// KVSynced is false while a configured KV v2 sync is still pending for
	// this password (failed, or waiting for kv_token). The periodic sweep
	// retries pending syncs without rotating. Always true when no KV sync
	// applies.
	KVSynced bool `json:"kv_synced"`
}

// getStaticCred loads the stored credential for a static role. Returns nil if none exists yet.
func getStaticCred(ctx context.Context, s logical.Storage, roleName string) (*staticCredEntry, error) {
	entry, err := s.Get(ctx, "static-creds/"+roleName)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var cred staticCredEntry
	if err := entry.DecodeJSON(&cred); err != nil {
		return nil, fmt.Errorf("error decoding static credential: %w", err)
	}
	return &cred, nil
}

// setStaticCred persists a static credential entry.
func setStaticCred(ctx context.Context, s logical.Storage, roleName string, cred *staticCredEntry) error {
	entry, err := logical.StorageEntryJSON("static-creds/"+roleName, cred)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

// rotateStaticCred unconditionally rotates (role writes need this: the
// rotation is the point of the write). The rotation lock makes the
// reset+store pair atomic with respect to all other rotation paths.
func (b *keycloakBackend) rotateStaticCred(ctx context.Context, s logical.Storage, roleName string, role *keycloakRoleEntry) error {
	b.rotationLock.Lock()
	defer b.rotationLock.Unlock()
	return b.rotateStaticCredLocked(ctx, s, roleName, role)
}

// errRotationInProgress signals that another rotation holds the lock; the
// scheduled sweep skips instead of blocking and retries on a later tick.
var errRotationInProgress = errors.New("another rotation is in progress")

// rotateStaticCredIfDue rotates only if the credential is still overdue once
// the rotation lock is held. It never blocks: a busy lock (another rotation
// in flight, possibly burning HTTP timeouts against a flaky Keycloak) returns
// errRotationInProgress so the sweep moves on. After acquiring the lock it
// re-checks the timestamp, so a manual rotation that completed in the
// meantime defers this scheduled one.
func (b *keycloakBackend) rotateStaticCredIfDue(ctx context.Context, s logical.Storage, roleName string, role *keycloakRoleEntry) error {
	if !b.rotationLock.TryLock() {
		return errRotationInProgress
	}
	defer b.rotationLock.Unlock()

	cred, err := getStaticCred(ctx, s, roleName)
	if err != nil {
		return err
	}
	if cred != nil && time.Since(cred.LastRotation) < role.RotationPeriod {
		return nil
	}
	return b.rotateStaticCredLocked(ctx, s, roleName, role)
}

// Periodic retry backoff: after f consecutive failures the next attempt waits
// min(1min << (f-1), 16min), so a struggling Keycloak is not hammered with
// full timeout-burning attempts on every tick. The role stays overdue the
// whole time (freshness is never sacrificed to the backoff: the very next
// allowed attempt rotates), and any successful rotation resets the state.
const maxRotationBackoff = 16 * time.Minute

// rotationBackoffRemaining returns how long the role must still wait before
// the next periodic rotation attempt, or zero if an attempt is allowed.
func (b *keycloakBackend) rotationBackoffRemaining(roleName string) time.Duration {
	b.backoffMu.Lock()
	defer b.backoffMu.Unlock()

	state := b.rotationBackoff[roleName]
	if state == nil || state.failures == 0 {
		return 0
	}
	delay := time.Minute << (state.failures - 1)
	if delay > maxRotationBackoff {
		delay = maxRotationBackoff
	}
	if remaining := time.Until(state.lastAttempt.Add(delay)); remaining > 0 {
		return remaining
	}
	return 0
}

// recordRotationFailure registers a failed periodic rotation attempt.
func (b *keycloakBackend) recordRotationFailure(roleName string) {
	b.backoffMu.Lock()
	defer b.backoffMu.Unlock()

	if b.rotationBackoff == nil {
		b.rotationBackoff = make(map[string]*rotationBackoffState)
	}
	state := b.rotationBackoff[roleName]
	if state == nil {
		state = &rotationBackoffState{}
		b.rotationBackoff[roleName] = state
	}
	state.failures++
	state.lastAttempt = time.Now()
}

// clearRotationBackoff forgets a role's failure history (successful rotation,
// role no longer overdue, or role deleted).
func (b *keycloakBackend) clearRotationBackoff(roleName string) {
	b.backoffMu.Lock()
	defer b.backoffMu.Unlock()
	delete(b.rotationBackoff, roleName)
}

// rotateStaticCredLocked generates a new password, sets it in Keycloak,
// stores the staticCredEntry, and optionally syncs to KV v2. Callers must
// hold rotationLock.
func (b *keycloakBackend) rotateStaticCredLocked(ctx context.Context, s logical.Storage, roleName string, role *keycloakRoleEntry) error {
	client, err := b.getClient(ctx, s)
	if err != nil {
		return err
	}

	password, err := generatePassword()
	if err != nil {
		return fmt.Errorf("error generating password: %w", err)
	}

	if err := client.ResetPassword(ctx, role.KeycloakUsername, password); err != nil {
		return fmt.Errorf("error rotating password for user %q: %w", role.KeycloakUsername, err)
	}

	// Crash window: if the process dies after Keycloak accepted the new
	// password but before the store below, storage holds a dead password.
	// Scheduled rotations self-heal on the next tick (the role is still
	// overdue). A crash inside a manual rotation can leave the dead password
	// until the schedule next elapses; a pending-rotation marker is tracked
	// in issue #50. No WAL at a 1-minute periodic cadence.

	config, cfgErr := getConfig(ctx, s)
	if cfgErr != nil {
		config = nil
	}

	cred := &staticCredEntry{
		Password:     password,
		LastRotation: time.Now(),
		KVSynced:     !kvSyncApplies(role, config),
	}
	if err := setStaticCred(ctx, s, roleName, cred); err != nil {
		return fmt.Errorf("error storing static credential: %w", err)
	}

	b.Logger().Info("static credential rotated",
		"role", roleName,
		"keycloak_username", role.KeycloakUsername,
	)

	if kvSyncApplies(role, config) {
		b.attemptKVSync(ctx, s, roleName, role, config, cred)
	}

	return nil
}

// kvSyncApplies reports whether a KV v2 sync is configured for this role.
func kvSyncApplies(role *keycloakRoleEntry, config *keycloakConfig) bool {
	return role.KVPasswordKey != "" && config != nil &&
		config.KVMountPath != "" && config.KVSecretPath != ""
}

// attemptKVSync tries to PATCH the credential's password into KV v2 and, on
// success, marks the stored entry as synced. On failure (or while kv_token is
// missing) the entry stays pending and the periodic sweep retries it on later
// ticks without rotating.
func (b *keycloakBackend) attemptKVSync(ctx context.Context, s logical.Storage, roleName string, role *keycloakRoleEntry, config *keycloakConfig, cred *staticCredEntry) {
	if config.KVToken == "" {
		b.Logger().Debug("kv sync pending: kv_token not configured", "role", roleName)
		return
	}
	vaultAddr := config.KVAPIAddr
	if vaultAddr == "" {
		vaultAddr = "https://127.0.0.1:8200"
	}
	if _, err := writeKVSecret(ctx, vaultAddr, config.KVToken, config.KVMountPath, config.KVSecretPath, role.KVPasswordKey, cred.Password, config.KVTLSSkipVerify); err != nil {
		b.Logger().Error("kv sync failed; will retry on the next periodic tick",
			"role", roleName,
			"kv_secret_path", config.KVSecretPath,
			"kv_password_key", role.KVPasswordKey,
			"error", err,
		)
		return
	}
	cred.KVSynced = true
	if err := setStaticCred(ctx, s, roleName, cred); err != nil {
		b.Logger().Error("failed to mark credential as kv-synced", "role", roleName, "error", err)
	}
}

// retryKVSync re-attempts a pending KV sync for a fresh credential. It runs
// under the rotation lock (TryLock) so it cannot interleave with an in-flight
// rotation's own KV write; a busy lock just skips to the next tick.
func (b *keycloakBackend) retryKVSync(ctx context.Context, s logical.Storage, roleName string, role *keycloakRoleEntry, config *keycloakConfig) {
	if !b.rotationLock.TryLock() {
		return
	}
	defer b.rotationLock.Unlock()

	cred, err := getStaticCred(ctx, s, roleName)
	if err != nil || cred == nil || cred.KVSynced {
		return
	}
	if !kvSyncApplies(role, config) {
		// KV sync was unconfigured after the entry was written: nothing to
		// deliver anymore, stop retrying.
		cred.KVSynced = true
		if err := setStaticCred(ctx, s, roleName, cred); err != nil {
			b.Logger().Error("failed to mark credential as kv-synced", "role", roleName, "error", err)
		}
		return
	}
	b.attemptKVSync(ctx, s, roleName, role, config, cred)
}

// periodicFunc is called by Vault approximately every minute. It rotates any
// static role whose rotation_period has elapsed since the last rotation.
func (b *keycloakBackend) periodicFunc(ctx context.Context, req *logical.Request) error {
	// Rotations mutate Keycloak and write to storage: only the primary
	// cluster's active node may do that. DR/performance secondaries and
	// performance standbys replicate the mount but have read-only storage;
	// without this guard they would fail (and log) every minute.
	if b.System().ReplicationState().HasState(
		consts.ReplicationDRSecondary |
			consts.ReplicationPerformanceSecondary |
			consts.ReplicationPerformanceStandby) {
		return nil
	}

	// Without a config there is no Keycloak to talk to: skip quietly instead
	// of logging a client-creation failure per overdue role on every tick.
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return fmt.Errorf("periodic: failed to load config: %w", err)
	}
	if config == nil {
		return nil
	}

	roles, err := req.Storage.List(ctx, "roles/")
	if err != nil {
		return fmt.Errorf("periodic: failed to list roles: %w", err)
	}

	// First pass: load every role and count how many map each username. Role
	// writes enforce exclusivity, but storage may predate that validation
	// (upgrades), and rotating a shared username would invalidate the other
	// role's stored password.
	loaded := make(map[string]*keycloakRoleEntry, len(roles))
	usernameCount := make(map[string]int, len(roles))
	for _, roleName := range roles {
		role, err := b.getRole(ctx, req.Storage, roleName)
		if err != nil {
			b.Logger().Error("periodic: failed to load role", "role", roleName, "error", err)
			continue
		}
		if role == nil {
			continue
		}
		loaded[roleName] = role
		usernameCount[role.KeycloakUsername]++
	}

	for _, roleName := range roles {
		role := loaded[roleName]
		if role == nil || role.Ephemeral {
			continue
		}
		// Defense in depth: a static role must have a positive rotation_period
		// (the getRole compat shim classifies rotation_period==0 as ephemeral).
		// Never rotate on a zero/negative period: with the time.Since check
		// below it would rotate the user's password on every periodic tick.
		if role.RotationPeriod <= 0 {
			b.Logger().Error("periodic: static role has no rotation_period; skipping",
				"role", roleName,
			)
			continue
		}
		if usernameCount[role.KeycloakUsername] > 1 {
			b.Logger().Error("periodic: keycloak_username is mapped by multiple roles; skipping rotation",
				"role", roleName,
				"keycloak_username", role.KeycloakUsername,
			)
			continue
		}

		cred, err := getStaticCred(ctx, req.Storage, roleName)
		if err != nil {
			b.Logger().Error("periodic: failed to load static cred", "role", roleName, "error", err)
			continue
		}

		needsRotation := cred == nil || time.Since(cred.LastRotation) >= role.RotationPeriod
		if !needsRotation {
			// A rotation succeeded since the last failure (scheduled or
			// manual): forget the failure history. If that rotation's KV sync
			// is still pending, retry it now without rotating.
			b.clearRotationBackoff(roleName)
			if !cred.KVSynced {
				b.retryKVSync(ctx, req.Storage, roleName, role, config)
			}
			continue
		}

		if wait := b.rotationBackoffRemaining(roleName); wait > 0 {
			b.Logger().Debug("periodic: backing off after failed rotations",
				"role", roleName,
				"retry_in", wait.Round(time.Second).String(),
			)
			continue
		}

		// IfDue: skips without blocking when another rotation holds the lock,
		// and re-checks the timestamp under the lock so a manual rotation
		// that completed in the meantime defers this scheduled one.
		switch err := b.rotateStaticCredIfDue(ctx, req.Storage, roleName, role); {
		case errors.Is(err, errRotationInProgress):
			b.Logger().Debug("periodic: another rotation in progress; skipping",
				"role", roleName,
			)
		case err != nil:
			b.recordRotationFailure(roleName)
			b.Logger().Error("periodic: rotation failed", "role", roleName, "error", err)
		default:
			b.clearRotationBackoff(roleName)
		}
	}

	return nil
}

// syncStaticCredsForUsername updates the stored staticCredEntry for every
// non-ephemeral role that maps to the given Keycloak username. Called after a
// manual rotation so the autorotation timer is reset to now.
func (b *keycloakBackend) syncStaticCredsForUsername(ctx context.Context, s logical.Storage, username, password string) error {
	roleNames, err := s.List(ctx, "roles/")
	if err != nil {
		return fmt.Errorf("failed to list roles: %w", err)
	}

	config, cfgErr := getConfig(ctx, s)
	if cfgErr != nil {
		config = nil
	}

	for _, roleName := range roleNames {
		role, err := b.getRole(ctx, s, roleName)
		if err != nil || role == nil {
			continue
		}
		if role.Ephemeral || role.KeycloakUsername != username {
			continue
		}

		cred := &staticCredEntry{
			Password:     password,
			LastRotation: time.Now(),
			KVSynced:     !kvSyncApplies(role, config),
		}
		if err := setStaticCred(ctx, s, roleName, cred); err != nil {
			b.Logger().Error("failed to update static cred after manual rotation",
				"role", roleName,
				"keycloak_username", username,
				"error", err,
			)
			continue
		}
		b.Logger().Info("static cred timer reset after manual rotation",
			"role", roleName,
			"keycloak_username", username,
		)

		if kvSyncApplies(role, config) {
			b.attemptKVSync(ctx, s, roleName, role, config, cred)
		}
	}

	return nil
}

// pathStaticCreds registers the static-creds/<name> read endpoint.
func pathStaticCreds(b *keycloakBackend) *framework.Path {
	return &framework.Path{
		Pattern: "static-creds/" + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeLowerCaseString,
				Description: "Name of the static role to read credentials for.",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathStaticCredsRead,
				Summary:  "Read the current password for a static (autorotated) Keycloak role.",
			},
		},
		HelpSynopsis:    pathStaticCredsHelpSyn,
		HelpDescription: pathStaticCredsHelpDesc,
	}
}

func (b *keycloakBackend) pathStaticCredsRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("name").(string)

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse("role %q not found", roleName), nil
	}
	if role.Ephemeral {
		return logical.ErrorResponse("role %q is ephemeral; use creds/%s", roleName, roleName), nil
	}

	cred, err := getStaticCred(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if cred == nil {
		return logical.ErrorResponse("no credential available for role %q; rotation pending", roleName), nil
	}

	resp := &logical.Response{
		Data: map[string]interface{}{
			"username":        role.KeycloakUsername,
			"password":        cred.Password,
			"last_rotation":   cred.LastRotation.Format(time.RFC3339),
			"rotation_period": role.RotationPeriod.Seconds(),
			"next_rotation":   cred.LastRotation.Add(role.RotationPeriod).Format(time.RFC3339),
		},
	}
	if role.KVPasswordKey != "" {
		resp.Data["kv_synced"] = cred.KVSynced
	}
	// Staleness signal: well past due means autorotation has been failing
	// (Keycloak unreachable, replication misconfiguration, ...). The password
	// is still the last one successfully set, so it remains valid.
	if role.RotationPeriod > 0 && time.Since(cred.LastRotation) > 2*role.RotationPeriod {
		resp.Warnings = append(resp.Warnings, fmt.Sprintf(
			"credential is overdue: last rotated %s ago with a rotation_period of %s; autorotation may be failing, check the Vault logs",
			time.Since(cred.LastRotation).Round(time.Second), role.RotationPeriod))
	}
	return resp, nil
}

const pathStaticCredsHelpSyn = `Read the current autorotated password for a static Keycloak role.`

const pathStaticCredsHelpDesc = `
Returns the most recently rotated password for the Keycloak user bound to
this static role. No lease is created — the same password is returned on
every read until the next autorotation.

Use creds/<name> for ephemeral lease-bound credentials instead.
`
