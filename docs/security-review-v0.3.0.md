# Security review: static roles and autorotation (v0.3.0)

Security review record for the `feat/autorotation` branch. It contains two
reviews:

1. **Full review (2026-06-11)** — full-source review, conducted and fully
   resolved before the v0.3.0 release. Every finding was fixed on the branch
   and verified (see the final gate in step 12). Steps are numbered in
   execution order, following priority P0 (critical) -> P1 (high) ->
   P2 (hardening) -> P3 (tests, docs, release hygiene).
2. **Follow-up review (2026-06-14)** — a focused re-review of rotation
   atomicity (final section). Its findings are OPEN and tracked as issues.

Commits are referenced by subject; the full sequence is visible in the v0.3.0
pull request.

---

## P0: Critical (fix first, each is a blocker)

### 1. Rebase onto main (done 2026-06-11; backup: `backup/feat-autorotation-pre-rebase`, local only)

Prerequisite for everything else (plan.md Step 8). Resolve all `.devcontainer/*`
conflicts in favour of main (plan.md Step 7), merge both sides of
`backend_test.go`. Note: the plan.md conflict table expects a `robfig/cron`
go.mod conflict; the branch never touched go.mod (PeriodicFunc replaced cron),
so no go.mod/go.sum conflict will occur.

### 2. Fix the legacy-role autorotation storm (done 2026-06-11, commit "fix(autorotation): never autorotate legacy roles without rotation_period")

- Files: `path_roles.go` (`normalizeRole` compat shim), `path_static_credentials.go` (`rotateRoleIfDuePeriodic`, the per-role periodic sweep)
- Problem: roles created on v0.1.x/v0.2.x without an explicit `ttl`
  (`GetOk` never applies schema defaults, so `TTL=0, MaxTTL=0` was stored) are
  classified as static with `RotationPeriod=0` after upgrade. `needsRotation`
  evaluates `time.Since(last) >= 0`, always true: the plugin rotates that
  production user's Keycloak password every minute, silently and forever, while
  `creds/<role>` starts erroring.
- Fix:
  - Shim: treat every role with `RotationPeriod == 0` as ephemeral,
    regardless of stored TTL values (legacy roles are always ephemeral).
  - Defense in depth: the periodic sweep (`rotateRoleIfDuePeriodic`) skips any role with `RotationPeriod <= 0`.
- Test: decode a v0.2.0-shaped role JSON fixture with `ttl=0`/no `ephemeral`
  field; assert it is ephemeral, never rotated by `periodicFunc`, and still
  usable via `creds/<role>`.

### 3. Fix the typed-nil client panic (done 2026-06-11, commit "fix(config): reject incomplete configs and never cache a typed-nil client")

- Files: `backend.go` (`getClient`), `path_config.go` (`pathConfigWrite`)
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

### 4. Restructure role write: validate -> rotate -> persist (done 2026-06-11, commit "fix(roles): rotate before persisting so failed writes leave prior state intact")

- File: `path_roles.go` (`pathRoleWrite`, with write/rotate/persist in `determineNeedsRotation` and `commitRole`)
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

### 5. Enforce username uniqueness across roles (done 2026-06-11, commit "fix(roles): enforce keycloak_username exclusivity across role modes"; periodic warn-and-skip default applied)

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

### 6. Serialize rotations with a lock (done 2026-06-11, commit "fix(autorotation): serialize rotations so storage cannot diverge from Keycloak")

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

### 7. Mode-switch and delete hygiene (REVISED 2026-06-11, commit "fix(roles): leave passwords operational on role delete and mode conversion")

DECISION REVISED (user, 2026-06-11): continuity-first design. The original
intent of the plugin is that Keycloak credentials remain operational if Vault
is decommissioned. Therefore role delete and static-to-ephemeral conversion
clean up Vault state ONLY (role entry, stored credential, stale fields); the
live Keycloak password intentionally keeps working. Discard-rotation applies
ONLY to lease revocation (defining lease semantic). Revocation on demand is
composable: users/<username>/rotate, then delete. The earlier strict variant
("fix(roles): discard the managed password on static role delete and mode switch", discard on both) was superseded by "fix(roles): leave passwords operational on role delete and mode conversion". Documented in README
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

### 7a. Config identity-change warning (added 2026-06-11, commit "feat(config): warn when the keycloak identity changes while roles exist")

Changing url or the effective target realm while roles exist re-points every
role's username at the new target (dangerous when the same username exists in
both realms). Config writes now return a Vault warning listing the change and
the role count. Documented in the README config section.

### 7b. Defer queued scheduled rotations after a manual rotation (added 2026-06-11, commit "fix(autorotation): defer a queued scheduled rotation after a manual rotation")

A scheduled rotation that was already in flight when a manual rotation
completed now re-checks last_rotation under the rotation lock and skips, so
the schedule always restarts from the manual rotation timestamp.

### 7c. Non-blocking sweep and failure backoff (added 2026-06-11)

Flaky-Keycloak hardening (user-requested after the lock-contention review):
the periodic sweep never blocks on the rotation lock (TryLock; busy means a
rotation is already in flight, so skip and retry on a later tick), and failed
periodic attempts back off exponentially per role (1m doubling, capped 16m,
in-memory, reset on any successful rotation, on a fresh credential, and on
role delete). Failures never consume the rotation schedule: the role stays
overdue and the next allowed attempt rotates, so recovery is exactly one
catch-up rotation per role, never a burst.

### 8. Replication-state guard and early exits in periodicFunc (done 2026-06-11, commit "fix(autorotation): guard periodicFunc against replication secondaries and missing config")

- File: `path_static_credentials.go` (`periodicFunc`)
- Fix:
  - Return early when
    `b.System().ReplicationState().HasState(consts.ReplicationDRSecondary | consts.ReplicationPerformanceSecondary | consts.ReplicationPerformanceStandby)`,
    matching HashiCorp's rotating engines, so Enterprise secondaries do not
    attempt writes to read-only storage every minute.
  - Return early when no config is stored, instead of logging a `getClient`
    failure per overdue role per minute.

### 9. KV sync retry and staleness signalling (done 2026-06-11, commit "fix(autorotation): retry pending KV syncs and surface credential staleness")

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

### 10. Integration coverage for autorotation (done 2026-06-11, commits "test(integration): cover static roles, autorotation semantics, and mode conversion" + "test(fuzz): guard the rotation-storm invariant and static credential decoding")

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

### 11. Documentation: security model and upgrade notes (branch side DONE across the fix commits; REMAINING: the stale "never stored by Vault" claim in .github/workflows/social.yml lives on MAIN, route via the docs/ci PR convention after this branch merges)

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

### 12. Final verification gate (run 2026-06-11 on the host; CI re-validates with pinned tooling on the PR)

RESULTS (2026-06-11): make pre-push GREEN (golangci-lint 0 issues, unit tests
with race detector ok, govulncheck no vulnerabilities, go-licenses clean);
make cover GREEN (82.2% total vs 72% floor, all file floors met);
make test-integration-matrix GREEN (40/40 on each of the 3 Vault legs:
1.14.10 MPL, 1.21.4, 2.0.2). Host-run parity notes: golangci-lint 2.12.2 vs
CI pin 2.11.4 and unlocked local Python deps; both re-validated by CI on the
PR. NOT done here: the kind dev environment manual pass (plan.md Step 10 is
not built yet); the unit + integration coverage above stands in for it.
Next: open the PR (plan.md Step 12, title `feat:` for v0.3.0).

---

## Explicitly out of scope (accepted or pre-existing)

- Plaintext static passwords in storage: inherent to static-role design,
  mitigated by the barrier + seal wrap; documented in step 11.
- `kv_tls_skip_verify` and ROPC master-admin credential: pre-existing v0.2.x
  surface, tracked separately from this feature branch.
- Crash between ResetPassword and storage write: self-heals on the next
  periodic tick; add a code comment, no WAL needed at a 1-minute cadence.

---

## Follow-up review — rotation atomicity (2026-06-14)

Focused re-review of the `feat/autorotation` branch, conducted on 2026-06-14
by the domain-tuned `security-reviewer` subagent against `git diff main...HEAD`.
Credential handling, trust boundaries, and input validation were re-confirmed
clean within the diff. The findings below are rotation-atomicity gaps at the
storage-write point; both relate to items addressed or accepted in the full
review above, and both are OPEN, tracked as issues.

> **Maintainer fact-check (2026-06-15).** The findings below were verified
> against the source before triage; the original subagent draft over-claimed
> on two points, corrected inline and marked **[corrected]**:
>
> - **F1** mis-described the mechanism. Two concurrent *identical* role writes
>   cannot split the password (the rotation lock makes `ResetPassword` +
>   `setStaticCred` atomic). The real gap is narrower and lower severity:
>   concurrent *conflicting* edits to the same role. Reframed below; tracked
>   as **issue #59** (low).
> - **F2** is not new: username exclusivity (finding #5) bounds the sync loop
>   to at most one static role, so the "partial loop" framing does not occur in
>   normal operation. It reduces to the manual-path crash window already
>   tracked as **issue #50**, where it has been recorded.
> - Line numbers in the original draft were fabricated; references below use
>   function names.

### Clean categories (re-confirmed 2026-06-14)

- **Credential handling**: no password, client secret, or bearer token is
  written to an `hclog` line, wrapped into an error, or returned outside the
  intended response fields. The bearer token stays in the `Authorization`
  header (`client.go`), never in a URL. `static-creds/*` is added to
  `SealWrapStorage` (`backend.go`).
- **Trust boundaries**: the new code makes no direct Keycloak HTTP calls; it
  routes through `keycloakClient`, whose admin calls check status before
  trusting the body and `url.QueryEscape` the username. The HTTP client has a
  30s timeout (`client.go`).
- **Input validation**: request fields reaching Keycloak are regex/type
  bounded (`name`, `username`); `rotation_period` has a 30-minute floor;
  `pathConfigWrite` rejects incomplete configs.

### F1. pathRoleWrite is not atomic against concurrent conflicting edits (low, OPEN) [corrected]

- File: `pathRoleWrite` (`path_roles.go`)
- Tracked as: **issue #59**.
- Relates to: finding #6 (rotation lock). #6 holds `b.rotationLock` across each
  `ResetPassword + setStaticCred` critical section inside `rotateStaticCred`,
  which serializes `periodicFunc`, `users/<name>/rotate`, and the role-write
  initial rotation against each other. This finding is the residual gap #6 does
  not cover: `pathRoleWrite` holds the lock only inside the nested
  `rotateStaticCred` call, not across its own read-modify-rotate-write handler.
  Vault does not serialize concurrent writes to the same logical path (engines
  self-lock with `locksutil` when they need it; this plugin does so only at the
  inner rotation).
- **[corrected] What does NOT happen:** the original draft claimed two
  concurrent identical role writes leave storage holding password Pa while
  Keycloak has Pb. That is impossible: the rotation lock makes
  `ResetPassword` + `setStaticCred` atomic, so the last locked section sets
  Keycloak and storage to the *same* password. `staticCredEntry` stores no
  username, so there is nothing to mismatch on identical writes.
- **[corrected] The real gap:** two concurrent writes that change the *same
  role* to *different* usernames (or a conversion-to-ephemeral racing a static
  write). The unlocked `setRole` / `static-creds` delete is last-writer-wins
  and can disagree with the cred the serialized rotation wrote: the role
  definition says username X while the stored cred holds the password set on
  user Y, or an orphaned cred survives a race with conversion. It does **not**
  self-heal on the next tick: the cred is freshly written, so the role is not
  overdue and `periodicFunc` will not re-rotate it for a full
  `rotation_period`.
- Severity: low. Requires concurrent *conflicting* edits to one role name (an
  unusual operator action); config writes are last-writer-wins regardless.
  Defense-in-depth.
- Fix direction: hold `b.rotationLock` (or a per-role lock) across the whole
  `pathRoleWrite` critical section (the `needsRotation` decision through
  `setRole` and the conversion-time `static-creds` delete), so
  decision-rotate-persist is atomic with respect to the other rotation paths.
- Test: two concurrent `pathRoleWrite` calls changing the same role to
  *different* usernames under `-race`; assert the persisted role's username and
  the stored cred's password belong to the same Keycloak user.

### F2. Manual rotation crash window can leave a static role serving a dead password (low, OPEN) [corrected]

- Files: `pathUsersRotate` (`path_users.go`),
  `syncStaticCredsForUsername` (`path_static_credentials.go`)
- Tracked as: **issue #50** (the verified scope is recorded there). The in-code
  comment in `rotateStaticCredLocked` already acknowledges this window, and the
  out-of-scope section above accepts the ResetPassword/storage crash window for
  the *periodic* path. This is the *manual* path variant, which does not
  self-heal on the same cadence.
- **[corrected] The original draft's framing ("partway through the per-role
  loop", several static roles left inconsistent) does not occur in normal
  operation.** Username exclusivity (finding #5) forbids a static role's
  username from being shared, so `syncStaticCredsForUsername` updates at most
  one static role per username. The multi-role partial-loop case exists only in
  legacy pre-exclusivity storage, which `periodicFunc` already excludes from
  rotation (its `usernameCount > 1` skip).
- Problem (verified scope): a single static role, manual `users/<name>/rotate`,
  process death after `ResetPassword` succeeds but before `setStaticCred`. The
  role keeps its old stored password, now dead in Keycloak. Because
  `LastRotation` is unchanged, the role is NOT overdue, so `periodicFunc` will
  not re-rotate it until a full `rotation_period` elapses (minimum 30 minutes;
  operator-set values widen the window).
- Fix direction: persist a pending-rotation marker (or a "needs reconcile"
  flag) before calling `ResetPassword`, and have `periodicFunc` reconcile any
  role whose stored password predates the last known manual rotation,
  independent of `rotation_period`.
- Test: inject a failure after `ResetPassword` (and, for the legacy multi-role
  case, after the first `setStaticCred`); assert `periodicFunc` reconciles the
  un-updated role on the next tick rather than waiting a full
  `rotation_period`.

### F3. Scheduled-path ordering is correct and self-healing (informational)

- File: `rotateStaticCredLocked` (`path_static_credentials.go`)
- The scheduled ordering is correct: `ResetPassword` (Keycloak) precedes
  `setStaticCred` (storage), so a crash in between leaves the role overdue and
  the next periodic tick re-rotates. The old password is invalidated
  immediately on success (no lingering valid old credential), and the new
  password is never "persisted but not activated" because Keycloak activation
  happens first. Residual exposure is only the manual path in F2.

### Relationship to the full review

- F1 narrows finding #6: the lock exists and covers the inner rotation, but not
  the outer `pathRoleWrite` handler.
- F2 is the manual-path instance of the crash window the full review accepted
  as out-of-scope for the periodic path; it is tracked as issue #50.
- No regression in the categories the full review hardened (credential leakage,
  trust boundaries, input validation) was found.
