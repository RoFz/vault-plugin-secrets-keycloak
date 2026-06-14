# Security review follow-up: rotation atomicity (v0.3.0)

Record of a focused re-review of the `feat/autorotation` branch, conducted on
2026-06-14 by the domain-tuned `security-reviewer` subagent against
`git diff main...HEAD`. This is a follow-up to the full review in
[`security-review-v0.3.0.md`](./security-review-v0.3.0.md) (conducted and
resolved 2026-06-11); read that first. Credential handling, trust boundaries,
and input validation were re-confirmed clean within the diff. The two findings
below are both rotation-atomicity gaps at the storage-write point, and both
relate to items already addressed or accepted in the original review, so each
is cross-referenced to its prior context. Status is OPEN: these are recorded
for triage, not yet fixed.

---

## Clean categories (re-confirmed 2026-06-14)

- **Credential handling**: no password, client secret, or bearer token is
  written to an `hclog` line, wrapped into an error, or returned outside the
  intended response fields. The bearer token stays in the `Authorization`
  header (`client.go`), never in a URL. `static-creds/*` is added to
  `SealWrapStorage` (`backend.go:60`).
- **Trust boundaries**: the new code makes no direct Keycloak HTTP calls; it
  routes through `keycloakClient`, whose admin calls check status before
  trusting the body and `url.QueryEscape` the username. The HTTP client has a
  30s timeout (`client.go:76`).
- **Input validation**: request fields reaching Keycloak are regex/type
  bounded (`name`, `username`); `rotation_period` has a 30-minute floor;
  `pathConfigWrite` rejects incomplete configs.

---

## Findings (OPEN)

### F1. Concurrent role writes can interleave the rotate/persist pair (med)

- File: `path_roles.go:130-220` (`pathRoleWrite`)
- Relates to: original finding #6 (rotation lock). #6 holds `b.rotationLock`
  across each `ResetPassword + setStaticCred` critical section inside
  `rotateStaticCred`, which serializes `periodicFunc`, `users/<name>/rotate`,
  and the role-write initial rotation against each other. This finding is the
  residual gap #6 does not cover: `pathRoleWrite` holds the lock only inside
  the nested `rotateStaticCred` call, not across its own
  read-modify-rotate-write handler.
- Problem: Vault's framework does not serialize two concurrent writes to the
  same logical path. Two simultaneous `POST roles/foo` requests (or a role
  write racing a periodic tick for a converting role) can interleave: request A
  rotates and is about to `setRole`; request B rotates again and persists; A
  then persists its older role/cred view. Storage ends up holding A's
  `staticCredEntry` (password Pa) while Keycloak's live password is B's (Pb),
  so `static-creds/foo` serves a dead password until the next periodic tick
  self-heals. Periodic self-heal makes this transient, not permanent: hence
  med, not high.
- Fix direction: hold `b.rotationLock` across the whole `pathRoleWrite`
  critical section (the `needsRotation` decision through `setRole`), or add a
  per-role lock around the entire handler, so decision-rotate-persist is atomic
  with respect to the other rotation paths.
- Test: two concurrent `pathRoleWrite` calls for the same role under `-race`;
  assert the stored password matches the last Keycloak reset.

### F2. Manual rotation crash window can leave static roles serving dead passwords (med)

- Files: `path_users.go:147-169` (`pathUsersRotate`),
  `path_static_credentials.go:1016-1060` (`syncStaticCredsForUsername`)
- Relates to: tracked as **issue #50**; the in-code comment at
  `path_static_credentials.go:805-810` already acknowledges this window, and
  the original review's out-of-scope section accepts the
  ResetPassword/storage crash window for the *periodic* path. This finding is
  the *manual* path variant, which does not self-heal on the same cadence.
- Problem: `pathUsersRotate` resets the Keycloak password first, then loops
  over every matching static role writing a fresh `staticCredEntry`. If the
  process dies after `ResetPassword` succeeds but partway through the per-role
  `setStaticCred` loop, the un-updated roles keep their old stored password,
  now dead in Keycloak. Unlike the scheduled path, these roles are NOT overdue
  (`LastRotation` is unchanged, still within `rotation_period`), so
  `periodicFunc` will not re-rotate them until a full period elapses (minimum
  30 minutes; operator-set values widen the window).
- Fix direction: persist a pending-rotation / WAL marker (or write the new
  `staticCredEntry` with a "needs reconcile" flag) before calling
  `ResetPassword`, and have `periodicFunc` reconcile any role whose stored
  password predates the last known manual rotation, independent of
  `rotation_period`.
- Test: simulate a crash mid-loop (inject failure after the first
  `setStaticCred`); assert `periodicFunc` reconciles the un-updated roles on
  the next tick rather than waiting a full `rotation_period`.

### F3. Scheduled-path ordering is correct and self-healing (informational)

- File: `path_static_credentials.go:790-836` (`rotateStaticCredLocked`)
- The scheduled ordering is correct: `ResetPassword` (Keycloak) precedes
  `setStaticCred` (storage), so a crash in between leaves the role overdue and
  the next periodic tick re-rotates. The old password is invalidated
  immediately on success (no lingering valid old credential), and the new
  password is never "persisted but not activated" because Keycloak activation
  happens first. Residual exposure is only the manual path in F2.

---

## Relationship to the original review

- F1 narrows original finding #6: the lock exists and covers the inner
  rotation, but not the outer `pathRoleWrite` handler.
- F2 is the manual-path instance of the crash window the original review
  accepted as out-of-scope for the periodic path (self-heals on the next
  tick); it is tracked as issue #50.
- No regression in the categories the original review hardened (credential
  leakage, trust boundaries, input validation) was found.
