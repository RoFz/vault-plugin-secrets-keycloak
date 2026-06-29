# Production hardening posture

This maps the plugin against HashiCorp's
[Vault production hardening](https://developer.hashicorp.com/vault/docs/concepts/production-hardening)
recommendations.

That guide hardens the **Vault server deployment**. Read against the plugin as
the subject, most items are met by the plugin itself, by design or by what it
deliberately avoids doing; the remainder are the operator's or set in Vault's
own configuration. This table is explicit about which items the plugin or this
repository owns and where each stands. The plugin-owned items were exercised
against a live Vault + Keycloak deployment (2026-06-16).

Each note opens with a standardized lead-in, then explains it.

## Legend

- ✅ **Met by the plugin**: the plugin or repository fulfills this itself, by design or by what it deliberately avoids doing.
- 🔧 **Not the plugin's to satisfy**: owned by the operator, by Vault's own configuration, or not applicable to this component type (the note says which). The plugin neither fulfills nor obstructs it, and many notes record how it cooperates.

## Baseline recommendations

| Recommendation | Status | Notes |
| --- | :---: | --- |
| Do not run as root | ✅ | **Met by the plugin:** it requires no root and runs as a non-privileged subprocess under Vault's user, requesting no privileges of its own and writing only through Vault's storage API, never the host filesystem. Whether the launching account is itself non-root stays the operator's choice. |
| Allow minimal write privileges | ✅ | **Met by the plugin:** it persists only through Vault's storage API and writes nothing to the host filesystem, so it adds no write privileges of its own to scope. |
| Use end-to-end TLS | ✅ | **Met by the plugin:** on its own hops to Keycloak (`url`) and the KV API (`kv_api_addr`) it verifies TLS by default, defaults `kv_api_addr` to `https`, and never downgrades on its own; the optional `kv_tls_skip_verify` is off by default and should stay `false` in production. The final endpoint URLs are operator input. |
| Disable swap | 🔧 | **Operator responsibility:** an OS setting on the Vault host. |
| Disable core dumps | 🔧 | **Operator responsibility:** an OS setting on the Vault host. |
| Use single tenancy | ✅ | **Met by the plugin:** it runs as a subprocess under Vault's own user (and, if ever shipped as a container image, under a single declared user), introducing no separate tenant. The bare-metal/VM/container host-topology preference stays the operator's. |
| Firewall traffic | ✅ | **Met by the plugin:** its only egress is to Keycloak and the Vault API, a minimal, predictable surface that is straightforward to firewall, and it opens no inbound listener of its own beyond the mTLS RPC Vault establishes. Writing the firewall rules stays the operator's. |
| Avoid root tokens | ✅ | **Met by the plugin:** it requires no root token. Callers are authorized by Vault's normal ACL system under least-privilege tokens, and downstream calls use the plugin's own configured credentials, not a Vault token. Revoking the initial root token after setup stays the operator's one-time step. |
| Configure user lockout | 🔧 | **Not applicable to a secrets engine:** user lockout applies to auth methods (AppRole, LDAP, Userpass), where Vault tracks failed logins. This plugin has no login surface of its own; the token that reaches it is issued and lockout-protected upstream by whichever auth method authenticated the caller. |
| Enable audit device logs | ✅ | **Met by the plugin:** its traffic is fully auditable, Vault core records every request and response to its paths and HMAC-hashes the secret strings by default, so nothing is logged in clear text, and the plugin is audit-clean in its own operational logs (it never logs secret values; passwords are omitted from both log lines and config reads). Enabling the audit device with `vault audit enable` stays the operator's. |
| Log file management | 🔧 | **Operator responsibility:** rotate, compress, and centralize Vault's logs. This is configured on the Vault host (logrotate, journald, a log shipper, or Vault's own `log_rotate_*` server settings); the plugin emits its lines through Vault's logger but has no say in how the files are managed. |
| Disable shell command history | ✅ | **Met by the repository:** to keep the plugin's own config secrets out of shell history, the README documents the history-safe input forms for `master_admin_password` and `kv_token`, stdin (`key=-`) and file (`key=@file`), alongside the inline form (see also "Use standard input for vault secrets"). Disabling shell history itself stays the operator's. |
| Keep a frequent upgrade cadence | ✅ | **Met by the repository:** staying current is easy and verifiable through SemVer releases, a changelog, cosign-signed artifacts, SBOMs, and automated dependency updates that keep the plugin's own dependencies patched. Applying the upgrade stays the operator's step. |
| Synchronize clocks | 🔧 | **Operator responsibility:** run NTP (or equivalent) so all Vault nodes agree on the time. The plugin reads the host wall clock for autorotation timing and keeps no clock of its own, so significant skew, especially across nodes in HA, can shift when a rotation fires after a failover. |
| Restrict storage access | ✅ | **Met by the plugin:** it marks its sensitive paths for seal-wrapping (`config`, `roles/*`, `static-creds/*`), so stored credentials are barrier-encrypted *and* seal-wrapped, an attacker with raw storage access still cannot read them. Locking down the storage backend itself (filesystem perms, Consul ACLs, Raft node access) stays the operator's. |
| Do not use clear text credentials | ✅ | **Met by the plugin:** the `master_admin_password` and `kv_token` are stored in Vault's encrypted, seal-wrapped storage and are write-only on read, never in clear text. (Supplying them via stdin/env is covered separately below.) |
| Use the safest algorithms available | ✅ | **Met by the plugin:** on its own outbound hops it pins no `tls.Config`, so it inherits Go's secure defaults, TLS 1.2 floor, TLS 1.3 ceiling, modern cipher suites, certificate verification on, and never downgrades. Hardening Vault's own TLS listener (which legacy suites it accepts) stays the operator's, set in the Vault server config. |
| Follow best practices for plugins | ✅ | **Met by the repository:** registration is SHA256-integrity-checked and version-pinned; release artifacts are cosign-signed with SBOMs plus a post-release validation report; the plugin loads only from a configured `plugin_directory`. |
| Be aware of non-deterministic config file merging | ✅ | **Met by the plugin:** its config is not file-based, it is a single storage object written through the `config` API path and merged field-by-field in deterministic code order, so the non-deterministic-merge problem does not arise for it. Vault's own HCL config-file merging (the directory-order concern) stays the operator's. |
| Use correct filesystem permissions | ✅ | **Met by the plugin:** it reads and writes no host files of its own (all state goes through Vault's storage API), so it introduces no files whose permissions need setting. Permissions on Vault's own files (binary, config, data dir, TLS keys) stay the operator's. |
| Use standard input for vault secrets | ✅ | **Met by the repository:** the README documents the history-safe input forms, stdin (`key=-`) and file (`key=@file`), for the plugin's own config secrets (`master_admin_password`, `kv_token`) alongside the inline form, so secrets need never be passed as inline arguments. The CLI mechanism is Vault's; whether to use it stays the operator's choice. |
| Develop an off-boarding process | ✅ | **Met by the plugin:** it supplies the revocation primitives off-boarding needs, `users/<username>/rotate` plus role delete to cut access on demand, and lease revoke for ephemeral credentials, so a departing identity's access can be severed immediately. Wiring these into an organizational process stays the operator's. |
| Use short TTLs | ✅ | **Met by the plugin:** ephemeral credentials are lease-bound and short-lived (issuance, renewal, revoke, and automatic TTL expiry validated end-to-end); static credentials rotate on a `rotation_period`. |
| Least privilege and bias towards simple policies | ✅ | **Met by the plugin:** its granular, separable paths (`config`, `roles`, `creds`, `static-creds`, `users`) are what make tight, simple policies possible, a consumer can be scoped to only `creds/<role>` and never `config`, and the README ships a tightly-scoped `kv_token` policy example. Writing the policy text stays the operator's. |

## Extended recommendations

| Recommendation | Status | Notes |
| --- | :---: | --- |
| Disable SSH / remote desktop | ✅ | **Met by the plugin:** it exposes no interactive or remote-access surface of its own, no SSH, no RDP, no shell, no general listener; its only inbound channel is the mTLS RPC Vault establishes and supervises. Disabling the host's own SSH/RDP daemons stays the operator's. |
| Use systemd security features | ✅ | **Met by the plugin:** it is compatible-by-design with tight systemd confinement, it needs no extra Linux capabilities, performs no privileged operations, and writes no host files, so `ProtectSystem=strict`, `PrivateTmp=true`, `NoNewPrivileges=true`, and a stripped capability set do not break it. Writing the unit-file directives stays the operator's. |
| Perform immutable upgrades | ✅ | **Met by the plugin:** it is compatible-by-design, it ships as a self-contained binary registered by SHA256 and version, so a new node or image carries the new binary and re-registers it with no in-place mutation of a running host (the README documents the register / upgrade / remove flow). Running the immutable-upgrade process stays the operator's. |
| Configure SELinux / AppArmor | ✅ | **Met by the plugin:** it makes only minimal, MAC-confineable access, no host-file writes, egress only to Keycloak and the Vault API, so it embodies the least-access state a tight SELinux/AppArmor profile enforces. Authoring and loading the profile on the host stays the operator's. |
| Adjust user limits (ulimits) | ✅ | **Met by the plugin:** its footprint is modest and bounded, it uses Go's pooled HTTP client and opens no unbounded files or connections, so it stays well within default ulimits. Tuning ulimits for the Vault process on the host stays the operator's. |
| Special container considerations (mlock) | 🔧 | **Operator responsibility:** mlock inside a container needs a supporting storage driver (`overlayfs2`). This is a Vault-container concern; the plugin does not call mlock, memory locking is a Vault-core feature. |
| Consider memory usage with `disable_mlock` + integrated storage | 🔧 | **Vault configuration:** a Vault server setting balancing OOM risk against swap exposure. The plugin cannot control mlock; it holds secrets only transiently in memory and writes none to disk itself, so encrypting the swap file (if `disable_mlock` is set) stays the operator's. |
| Consider a separate partition for integrated storage | ✅ | **Met by the plugin:** its stored data is small and bounded (one config object, one entry per role and per static credential), with no per-request growth, so it cannot consume all storage. The partition layout on the Vault host stays the operator's. |
| Use an administrative namespace | 🔧 | **Vault configuration:** Vault Enterprise administrative namespaces enforce least privilege for admin operations. The plugin mounts in whatever namespace the operator chooses and neither requires nor obstructs an administrative namespace. |
| Authenticated reverse proxy | 🔧 | **Operator responsibility:** an authenticated reverse proxy is defense in depth in front of Vault's API; the plugin sits behind Vault and cannot provide it. (Its release hygiene, see "Keep a frequent upgrade cadence", reduces the stale-version risk this recommendation guards against for the plugin's own part.) |
| Use an outbound network proxy | ✅ | **Met by the plugin:** it sets no custom HTTP transport, so both egress hops honor standard proxy environment variables (Go's `ProxyFromEnvironment`; the KV hop additionally honors `VAULT_HTTP_PROXY`/`VAULT_PROXY_ADDR`), and its egress endpoints are limited and predictable (Keycloak and the Vault API), so its traffic is observable and routable through an outbound proxy. Deploying the proxy stays the operator's. |

## Summary

Of HashiCorp's 35 baseline and extended recommendations, **26 are met by the
plugin or this repository** and 9 are the deploying operator's responsibility or
set in Vault's own configuration. There are no partial items.

**Met by the plugin or repository (✅):**

- **Privilege and isolation:** no root required (#1), minimal write privileges (#2), single tenancy (#6), no root token required (#8), no host files of its own to permission (#20), granular least-privilege paths (#24), no remote-access surface (E1), compatible with tight systemd confinement (E2), minimal MAC-confineable access (E4).
- **Credential protection:** no clear-text credentials (#16), seal-wrapped storage with restricted blast radius (#15), short-lived / rotated credentials (#23), off-boarding revocation primitives (#22).
- **Transport, network, and egress:** end-to-end TLS on its own hops (#3), safe TLS defaults / algorithms (#17), minimal firewallable egress (#7), outbound-proxy compatible (E11).
- **Observability and config integrity:** fully auditable and audit-clean under Vault's HMAC (#10), deterministic API-driven config merge (#19).
- **Resource footprint:** stays within default ulimits (E5), small bounded storage footprint (E8).
- **Supply chain and lifecycle:** plugin and registration best practices (#18), easy/verifiable upgrade cadence (#13), immutable-upgrade compatible (E3), history-safe secret entry (#21, #12).

The remaining 9 are the operator's responsibility or Vault configuration (🔧),
items the plugin genuinely has no property to embody: disable swap (#4) and core
dumps (#5), user lockout (#9, not applicable, no auth surface), log file
management (#11), clock synchronization (#14, it consumes host time and runs no
NTP), mlock inside a container (E6) and `disable_mlock` memory tuning (E7), an
administrative namespace (E9), and an authenticated reverse proxy (E10). The
plugin is designed not to obstruct any of them.
