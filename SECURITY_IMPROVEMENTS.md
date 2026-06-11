# Security Improvements Plan: feat/autorotation

Source: full-source security review of the `feat/autorotation` branch (2026-06-11).
Scope: all findings must be resolved on this branch before the v0.3.0 PR opens.
Steps are numbered in execution order, which follows priority: P0 (critical,
blocking) -> P1 (high) -> P2 (hardening) -> P3 (tests, docs, release hygiene).

Status legend: [ ] pending, [x] done.

---

## P0: Critical (fix first, each is a blocker)

### 1. [x] Rebase onto main (done 2026-06-11; backup: `backup/feat-autorotation-pre-rebase`, local only)

Prerequisite for everything else (plan.md Step 8). Resolve all `.devcontainer/*`
conflicts in favour of main (plan.md Step 7), merge both sides of
`backend_test.go`. Note: the plan.md conflict table expects a `robfig/cron`
go.mod conflict; the branch never touched go.mod (PeriodicFunc replaced cron),
so no go.mod/go.sum conflict will occur.

### 2. [x] Fix the legacy-role autorotation storm (done 2026-06-11, commit 9b45c7f)

- Files: `path_roles.go` (compat shim, lines 245-251), `path_static_credentials.go` (`periodicFunc`, line 119)
- Problem: roles created on v0.1.x/v0.2.x without an explicit `ttl`
  (`GetOk` never applies schema defaults, so `TTL=0, MaxTTL=0` was stored) are
  classified as static with `RotationPeriod=0` after upgrade. `needsRotation`
  evaluates `time.Since(last) >= 0`, always true: the plugin rotates that
  production user's Keycloak password every minute, silently and forever, while
  `creds/<role>` starts erroring.
- Fix:
  - Shim: treat every role with `RotationPeriod == 0` as ephemeral,
    regardless of stored TTL values (legacy roles are always ephemeral).
  - Defense in depth: `periodicFunc` skips any role with `RotationPeriod <= 0`.
- Test: decode a v0.2.0-shaped role JSON fixture with `ttl=0`/no `ephemeral`
  field; assert it is ephemeral, never rotated by `periodicFunc`, and still
  usable via `creds/<role>`.

### 3. [x] Fix the typed-nil client panic (done 2026-06-11, commit d7709c1)

- Files: `backend.go` (line 97), `path_config.go` (`pathConfigWrite`)
- Problem: `b.client, err = newClient(config)` stores a nil `*keycloakClient`
  into the `keycloakClientIface` field on failure. The interface is then
  non-nil, so every later `getClient` returns the typed-nil client with no
  error and the next method call panics the plugin process. Reachable because
  `pathConfigWrite` accepts incomplete configs (`Required: true` is not
  enforced by the framework for body fields).
- Fix:
  - Assign `newClient` to a local `*keycloakClient`; set `b.client` only on success.
  - Re-check `b.client != nil` after acquiring the write lock (also closes the
    pre-existing lock-upgrade double-create race).
  - Validate required fields (`url`, `master_admin_username`,
    `master_admin_password`) in `pathConfigWrite` and reject incomplete writes.
- Test: write a config with only `url`, read `creds/<role>` twice; assert a
  clean error both times (no panic). Unit test for required-field validation.

---

## P1: High (correctness and credential-integrity bugs)

### 4. [x] Restructure role write: validate -> rotate -> persist (done 2026-06-11, commit 79d240d)

- File: `path_roles.go` (`pathRoleWrite`, lines 189-207)
- Problems:
  - On initial-rotation failure the rollback deletes `roles/<name>`, which
    destroys a pre-existing role when converting ephemeral -> static.
  - Changing `keycloak_username` on a static role does not rotate, so
    `static-creds/<name>` serves the NEW username paired with the OLD user's
    password (invalid pair, and leaks one user's password under another's name)
    until the next scheduled rotation.
- Fix: perform the rotation first using the in-memory role (when the role is
  new, the username changed, or the mode switched to static), persist the role
  only after rotation succeeds. No rollback path needed. Best-effort delete of
  the orphan static-cred if the role persist itself fails.
- Test: failed rotation on an update leaves the previous role intact;
  username change triggers immediate rotation and a matching cred pair.

### 5. [x] Enforce username uniqueness across roles (done 2026-06-11, commit 86ca9e8; periodic warn-and-skip default applied)

- File: `path_roles.go` (`pathRoleWrite`)
- Problem: nothing prevents one Keycloak username from being mapped by multiple
  roles. Two static roles on the same username invalidate each other on every
  periodic run (each rotation makes the other's stored password dead). A static
  and an ephemeral role on the same username let lease revocation
  (`secretRevoke` rotates to a discarded password) silently break
  `static-creds` for up to a full `rotation_period`.
- Fix: at role-write time, reject a static role whose `keycloak_username` is
  already used by any other static role or any ephemeral role, and reject an
  ephemeral role whose username is used by any static role.
  (Ephemeral + ephemeral sharing stays allowed: existing v0.2.x behaviour.)
- Decision needed: roles violating this that already exist in storage at
  upgrade time: warn-and-skip in `periodicFunc`, or hard skip. Default
  proposal: log a warning and skip rotation for the conflicting role.
- Test: rejection matrix for all four combinations; upgrade fixture with a
  pre-existing conflict.

### 6. [x] Serialize rotations with a lock (done 2026-06-11, commit fbcb212)

- Files: `path_static_credentials.go` (`rotateStaticCred`,
  `syncStaticCredsForUsername`), `path_users.go` (`pathUsersRotate`)
- Problem: `periodicFunc`, `users/<name>/rotate`, and role-write initial
  rotation can interleave ResetPassword/setStaticCred pairs, leaving storage
  holding password A while Keycloak has password B. `static-creds` then serves
  an invalid password until the next rotation.
- Fix: a backend-level `sync.Mutex` held across every
  ResetPassword + setStaticCred critical section. Rotations are rare; full
  serialization is acceptable and simplest to reason about.
- Test: concurrent manual rotate + periodic rotate under `-race`; assert the
  stored password matches the last Keycloak reset.

---

## P2: Hardening

### 7. [x] Mode-switch and delete hygiene (REVISED 2026-06-11, commit 0bab367)

DECISION REVISED (user, 2026-06-11): continuity-first design. The original
intent of the plugin is that Keycloak credentials remain operational if Vault
is decommissioned. Therefore role delete and static-to-ephemeral conversion
clean up Vault state ONLY (role entry, stored credential, stale fields); the
live Keycloak password intentionally keeps working. Discard-rotation applies
ONLY to lease revocation (defining lease semantic). Revocation on demand is
composable: users/<username>/rotate, then delete. The earlier strict variant
(211dee0, discard on both) was superseded by 0bab367. Documented in README
(security model, roles reference, lifecycle diagram).

- File: `path_roles.go`
- Problems: static -> ephemeral leaves the `static-creds/<name>` entry (a
  stale plaintext password, likely still valid in Keycloak, now unmanaged) and
  a stale `RotationPeriod`; ephemeral -> static leaves stale `TTL`/`MaxTTL`;
  deleting a static role leaves its last password valid in Keycloak forever.
- Fix: on mode switch, delete the static-cred entry and zero the
  no-longer-relevant fields. On static -> ephemeral switch and on static role
  delete, rotate the Keycloak password to a discarded value (consistent with
  the existing `secretRevoke` semantics).
- Decision needed: confirm discard-rotation on delete and on switch
  (recommended: yes to both). If declined, document the dangling-password
  behaviour prominently instead.

### 7a. [x] Config identity-change warning (added 2026-06-11, commit e561efb)

Changing url or the effective target realm while roles exist re-points every
role's username at the new target (dangerous when the same username exists in
both realms). Config writes now return a Vault warning listing the change and
the role count. Documented in the README config section.

### 7b. [x] Defer queued scheduled rotations after a manual rotation (added 2026-06-11, commit e84f144)

A scheduled rotation that was already in flight when a manual rotation
completed now re-checks last_rotation under the rotation lock and skips, so
the schedule always restarts from the manual rotation timestamp.

### 7c. [x] Non-blocking sweep and failure backoff (added 2026-06-11)

Flaky-Keycloak hardening (user-requested after the lock-contention review):
the periodic sweep never blocks on the rotation lock (TryLock; busy means a
rotation is already in flight, so skip and retry on a later tick), and failed
periodic attempts back off exponentially per role (1m doubling, capped 16m,
in-memory, reset on any successful rotation, on a fresh credential, and on
role delete). Failures never consume the rotation schedule: the role stays
overdue and the next allowed attempt rotates, so recovery is exactly one
catch-up rotation per role, never a burst.

### 8. [x] Replication-state guard and early exits in periodicFunc (done 2026-06-11, commit 51cfdfd)

- File: `path_static_credentials.go` (`periodicFunc`)
- Fix:
  - Return early when
    `b.System().ReplicationState().HasState(consts.ReplicationDRSecondary | consts.ReplicationPerformanceSecondary | consts.ReplicationPerformanceStandby)`,
    matching HashiCorp's rotating engines, so Enterprise secondaries do not
    attempt writes to read-only storage every minute.
  - Return early when no config is stored, instead of logging a `getClient`
    failure per overdue role per minute.

### 9. [x] KV sync retry and staleness signalling (done 2026-06-11, commit 6229217)

- Files: `path_static_credentials.go`, `path_roles.go` (entry struct)
- Problems: a failed KV sync after a successful Keycloak rotation leaves the
  KV copy dead for up to a full `rotation_period` (only logged). Consumers of
  `static-creds` cannot tell that rotation has been failing.
- Fix:
  - Add `kv_synced bool` to `staticCredEntry`; `periodicFunc` retries the KV
    sync for unsynced entries on each tick without rotating.
  - `static-creds` read: add a response warning when
    `time.Since(LastRotation) > 2 * RotationPeriod`, and add a `next_rotation`
    field (parity with Vault DB static creds).

---

## P3: Tests, docs, release hygiene

### 10. [x] Integration coverage for autorotation (done 2026-06-11, commits 4d3fcc7 + 2ac1432)

DONE. Note: plan.md Step 9's cherry-pick instructions were stale (that branch
predates the rebase and would have regressed main's newer test infra:
versions.env, requirements.lock, env-parametrized conftest). The test CONTENT
was ported instead and adapted to the post-review semantics (username
exclusivity, continuity-first conversion, kv_synced/next_rotation fields).
40/40 integration tests pass locally (Vault 1.21.4 leg). Also added two fuzz
targets per the P3 fuzz assessment: FuzzNormalizeRoleInvariant (rotation-storm
guard over the whole input space; 264k execs clean) and
FuzzStaticCredEntryDecode. Original scope:
cherry-pick the integration suite (plan.md Step 9), then extend it:
end-to-end static role lifecycle (create -> read -> autorotate -> read),
legacy-upgrade fixture, mode-switch flows, shared-username rejection, manual
rotate resets the timer. Keep unit coverage above the `.testcoverage.yml`
floors (`make cover`).

### 11. [ ] Documentation: security model and upgrade notes

- README: security-model section covering: static passwords are stored in
  Vault storage (plaintext within the barrier, `static-creds/*` is
  seal-wrapped on Enterprise); writing a static role immediately rotates the
  target user's existing password (a `roles/*` write grant is effectively a
  password-reset capability); delete/switch semantics from step 7.
- Upgrade notes for v0.2.x users: legacy roles are treated as ephemeral; how
  to migrate a role to static.
- After rebase, fix the stale "never stored by Vault" claim in
  `.github/workflows/social.yml` (on main; route per the docs-PR convention).
- Update plan.md: drop the stale robfig/cron conflict row from Step 8.

### 12. [ ] Final verification gate

`make lint`, `make test-unit`, `make cover`, `make test-integration-matrix`,
plus a manual pass in the kind dev environment (plan.md Step 10) exercising:
incomplete config (no panic), legacy role upgrade, autorotation at the minimum
period, KV sync failure recovery. Then open the PR (plan.md Step 12, title
`feat:` for v0.3.0).

---

## Explicitly out of scope (accepted or pre-existing)

- Plaintext static passwords in storage: inherent to static-role design,
  mitigated by the barrier + seal wrap; documented in step 11.
- `kv_tls_skip_verify` and ROPC master-admin credential: pre-existing v0.2.x
  surface, tracked separately from this feature branch.
- Crash between ResetPassword and storage write: self-heals on the next
  periodic tick; add a code comment, no WAL needed at a 1-minute cadence.
