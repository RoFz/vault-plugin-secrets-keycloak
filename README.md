# Vault Plugin: Keycloak Secrets Engine

[![CI](https://github.com/RoFz/vault-plugin-secrets-keycloak/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/RoFz/vault-plugin-secrets-keycloak/actions/workflows/ci.yml)
[![CodeQL](https://github.com/RoFz/vault-plugin-secrets-keycloak/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/RoFz/vault-plugin-secrets-keycloak/actions/workflows/codeql.yml)
[![Release](https://img.shields.io/github/v/release/RoFz/vault-plugin-secrets-keycloak)](https://github.com/RoFz/vault-plugin-secrets-keycloak/releases/latest)
[![Go](https://img.shields.io/badge/go-1.26-blue)](https://go.dev/doc/go1.26)
[![License](https://img.shields.io/github/license/RoFz/vault-plugin-secrets-keycloak)](LICENSE)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/12363/badge)](https://www.bestpractices.dev/projects/12363)

A HashiCorp Vault secrets engine plugin for Keycloak. Performs on-demand,
audit-logged user password rotation via the Keycloak Admin REST API. Each
rotation generates a cryptographically random password, sets it on the
Keycloak account, and returns the new value — with no credential stored
inside Vault.

## Contents

- [Vault Plugin: Keycloak Secrets Engine](#vault-plugin-keycloak-secrets-engine)
  - [Contents](#contents)
  - [What this plugin does](#what-this-plugin-does)
  - [What this plugin does not do](#what-this-plugin-does-not-do)
  - [Process flow](#process-flow)
  - [Installation](#installation)
    - [Download pre-built binaries](#download-pre-built-binaries)
    - [Build from source](#build-from-source)
    - [Deploy to a running Vault instance](#deploy-to-a-running-vault-instance)
      - [Kubernetes / FluxCD (recommended)](#kubernetes--fluxcd-recommended)
    - [Direct manifest method (fallback)](#direct-manifest-method-fallback)
      - [Copy binary to the Vault pod](#copy-binary-to-the-vault-pod)
      - [Register and enable](#register-and-enable)
      - [Upgrade or remove](#upgrade-or-remove)
  - [Configuration](#configuration)
    - [KV v2 sync (optional)](#kv-v2-sync-optional)
      - [Creating the KV sync token](#creating-the-kv-sync-token)
  - [Multiple Keycloak contexts (untested)](#multiple-keycloak-contexts-untested)
  - [Expected logs](#expected-logs)
  - [API reference](#api-reference)
    - [`config`](#config)
    - [`roles/<name>`](#rolesname)
    - [`users/`](#users)
    - [`users/<username>`](#usersusername)
    - [`users/<username>/rotate`](#usersusernamerotate)
    - [`creds/<name>` (alpha)](#credsname-alpha)
  - [Usage](#usage)
  - [Credential lifecycle](#credential-lifecycle)
  - [Contributing](#contributing)
  - [Security](#security)
  - [License](#license)

## What this plugin does

This plugin mounts as a Vault secrets engine and provides endpoints to:

- **List and read users** in the target Keycloak realm.
- **Rotate a user password on demand** via `users/<username>/rotate`
  (fire-and-forget — no lease, no expiration). The new password is
  returned to the caller and remains valid in Keycloak until the next
  explicit rotation.
- **Sync rotated passwords to a KV v2 secret** (v0.2.0+) — optionally
  PATCH the new password into another Vault KV v2 path after rotation
  (useful for Kubernetes secret operators).
- **Issue ephemeral, lease-bound credentials** via `creds/<role>`
  (alpha). The password is returned with a Vault lease; on lease expiry
  or explicit revocation, the plugin resets the Keycloak password to a
  random discarded value, invalidating both sides.

## What this plugin does not do

- **Create or delete Keycloak users.** The plugin only manages passwords
  for existing users.
- **Auto-rotate passwords on a schedule.** There is no background task
  or periodic rotation. All rotations are triggered by an explicit API
  call.
- **Store passwords inside Vault.** Rotated passwords are returned to
  the caller and (optionally) synced to a KV v2 path, but the plugin
  itself retains no record of them.

## Process flow

```mermaid
flowchart TD
  A[Operator calls Vault path] --> B{Path}
  B -->|keycloak/config| C[Store config in Vault storage]
  C --> D[Test Keycloak connection via admin token]
  B -->|keycloak/roles/name| E[Store role → keycloak_username mapping]
  B -->|keycloak/creds/role| F[Load role and config]
  F --> G[Generate random password]
  G --> H[Call Keycloak Admin API reset-password]
  H --> I{KV sync configured?}
  I -->|yes| I2[PATCH password into KV v2 secret]
  I2 --> I3[Return username and new password]
  I -->|no| I3
  B -->|keycloak/users| J[List users in target realm]
  B -->|keycloak/users/username| K[Read user details]
  B -->|keycloak/users/username/rotate| L[Generate password + reset in Keycloak]
  L --> M[Return username and new password]
```

## Installation

### Download pre-built binaries

Pre-built binaries for Linux, macOS, Windows, and FreeBSD (amd64 and arm64
where applicable) are published on the
[Releases page](https://github.com/RoFz/vault-plugin-secrets-keycloak/releases).

Download the binary for your platform and verify the SHA-256 checksum from
`checksums.txt`. The binary file name embeds the release version
(`vault-plugin-secrets-keycloak_<version>_<os>_<arch>`), so resolve the latest
version first:

```bash
# Example: Linux amd64
VERSION=$(curl -fsSL https://api.github.com/repos/RoFz/vault-plugin-secrets-keycloak/releases/latest | jq -r .tag_name)
BINARY="vault-plugin-secrets-keycloak_${VERSION#v}_linux_amd64"
BASE="https://github.com/RoFz/vault-plugin-secrets-keycloak/releases/download/${VERSION}"

curl -fLO "${BASE}/${BINARY}"
curl -fLO "${BASE}/checksums.txt"
sha256sum --check --ignore-missing checksums.txt
```

### Build from source

Requires Go 1.26+.

```bash
git clone https://github.com/RoFz/vault-plugin-secrets-keycloak.git
cd vault-plugin-secrets-keycloak
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -o vault-plugin-secrets-keycloak ./cmd/vault-plugin-secrets-keycloak
```

Adjust `GOOS` and `GOARCH` for your target platform.

### Deploy to a running Vault instance

The plugin binary must reside in Vault's
[plugin directory](https://developer.hashicorp.com/vault/docs/plugins/plugin-management#plugin-directory).

**Requirements before deploying:**

- A running Vault instance with a writable plugin directory (e.g. `/vault/plugins`).
- A Vault token with permission to register and enable plugins.
- Keycloak admin credentials for the target realm.

#### Kubernetes / FluxCD (recommended)

Manage the plugin volume using your FluxCD Kustomization and a HelmRelease patch.

1. Add a PVC manifest to the same Flux-managed folder used by your Vault release.
2. Add a patch file targeting your Vault HelmRelease to mount the PVC at `/vault/plugins`.
3. Reference both in the Kustomization (`resources` + `patches`/`patchesStrategicMerge`).
4. Commit and push, then reconcile Flux.

Example HelmRelease patch snippet:

```yaml
apiVersion: helm.toolkit.fluxcd.io/v2
kind: HelmRelease
metadata:
  name: vault
  namespace: vault
spec:
  values:
    server:
      extraVolumes:
        - name: plugin-dir
          persistentVolumeClaim:
            claimName: vault-plugin-pvc
      volumeMounts:
        - name: plugin-dir
          mountPath: /vault/plugins
```

Example Flux reconcile command:

```bash
flux reconcile kustomization <vault-kustomization-name> -n flux-system
```

### Direct manifest method (fallback)

Example PVC manifest for plugin storage:

```yaml
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: vault-plugin-pvc
  namespace: vault
spec:
  accessModes:
    - ReadWriteOnce
  resources:
    requests:
      storage: 1Gi
```

Example StatefulSet volume wiring (required so `/vault/plugins` exists in the pod):

```yaml
spec:
  template:
    spec:
      containers:
        - name: vault
          volumeMounts:
            - name: plugin-dir
              mountPath: /vault/plugins
      volumes:
        - name: plugin-dir
          persistentVolumeClaim:
            claimName: vault-plugin-pvc
```

#### Copy binary to the Vault pod

Copy binary to the active Vault pod:

```bash
kubectl cp ./vault-plugin-secrets-keycloak vault/vault-0:/vault/plugins/vault-plugin-secrets-keycloak
kubectl exec -n vault vault-0 -- chmod 0755 /vault/plugins/vault-plugin-secrets-keycloak
```

Compute SHA256 from inside the pod (used for plugin registration):

```bash
kubectl exec -n vault vault-0 -- sha256sum /vault/plugins/vault-plugin-secrets-keycloak
```

In an HA cluster with a shared plugin volume, verify all Vault server pods see
the same binary:

```bash
for pod in $(kubectl get pods -n vault -l component=server -o name); do
  echo "$pod:"
  kubectl exec -n vault "$pod" -- sha256sum /vault/plugins/vault-plugin-secrets-keycloak
done
```

All SHA256 values must match before proceeding.

#### Register and enable

Register and enable the plugin (the `-version` flag must match the version
reported by the binary):

```bash
SHA256=$(kubectl exec -n vault vault-0 -- sha256sum /vault/plugins/vault-plugin-secrets-keycloak | cut -d' ' -f1)
VERSION="vX.Y.Z"

vault plugin register -sha256="$SHA256" -version="$VERSION" secret vault-plugin-secrets-keycloak
vault secrets enable -path=keycloak vault-plugin-secrets-keycloak
```

#### Upgrade or remove

To upgrade or remove the plugin, first disable the secrets engine, then
deregister the plugin with the version it was registered under:

```bash
vault secrets disable keycloak/
vault plugin deregister -version="$VERSION" secret vault-plugin-secrets-keycloak
```

## Configuration

Write the plugin configuration (one config per mount):

```bash
vault write keycloak/config \
  url="https://keycloak.example.com" \
  realm="master" \
  target_realm="myrealm" \
  master_admin_username="admin" \
  master_admin_password='<admin-password>'
```

### KV v2 sync (optional)

When a password is rotated via `creds/<role>` or `users/<username>/rotate`,
the plugin can optionally PATCH the new password into a KV v2 secret in
Vault. This is useful for syncing rotated credentials to Kubernetes secrets
(via the Vault Secrets Operator or External Secrets Operator).

To enable KV sync, add the KV fields to the config:

```bash
vault write keycloak/config \
  url="https://keycloak.example.com" \
  master_admin_username="admin" \
  master_admin_password='<admin-password>' \
  kv_mount_path="k8s" \
  kv_secret_path="keycloak/realm-users" \
  kv_token="hvs.<token>" \
  kv_api_addr="https://vault.vault.svc.cluster.local:8200"
```

Then set `kv_password_key` on each role:

```bash
vault write keycloak/roles/myuser \
  keycloak_username="myuser" \
  kv_password_key="myuser-password"
```

After each `vault read keycloak/creds/myuser`, the plugin PATCHes
`k8s/data/keycloak/realm-users` with `{ "myuser-password": "<new-pw>" }`.
If the KV secret does not yet exist, a PUT (create) is used instead.

For ad-hoc rotations via the users path, pass it as a parameter:

```bash
vault write keycloak/users/myuser/rotate kv_password_key="myuser-password"
```

KV sync failures are non-fatal — the rotation still succeeds and a warning
is returned in the response.

#### Creating the KV sync token

The KV sync token needs `create`, `update`, and `patch` capabilities on the
target KV data path. Create a scoped policy and an orphan token:

```bash
vault policy write keycloak-kv-sync - <<'POLICY'
path "k8s/data/keycloak/realm-users" {
  capabilities = ["create", "update", "patch"]
}
POLICY

vault token create \
  -policy=keycloak-kv-sync \
  -orphan \
  -explicit-max-ttl=8760h \
  -ttl=8760h \
  -display-name=keycloak-kv-sync
```

> **`explicit-max-ttl` vs `max_lease_ttl`:** The token auth mount has a
> `max_lease_ttl` (default 768h / 32 days) that caps the initial TTL.
> The `-explicit-max-ttl` flag sets the absolute maximum lifetime of the
> token, up to which it can be renewed. The token must be renewed before
> its current TTL expires. For example, with `-ttl=8760h` and a mount
> `max_lease_ttl` of 768h, the token is created with a 768h TTL but can
> be renewed repeatedly until the `explicit-max-ttl` of 8760h is reached.

Adjust the policy path to match your `kv_mount_path` and `kv_secret_path`.

## Multiple Keycloak contexts (untested)

> **Untested:** multiple mount paths are expected to work based on how Vault
> handles plugin mounts, but this has not been validated against multiple
> Keycloak realms or deployments.

The plugin stores one config per mount path. To manage multiple Keycloak
deployments or realms, enable the plugin at multiple mount paths:

```bash
vault secrets enable -path=keycloak-appA vault-plugin-secrets-keycloak
vault secrets enable -path=keycloak-appB vault-plugin-secrets-keycloak

vault write keycloak-appA/config \
  url="https://keycloak.example.com" \
  realm="master" \
  target_realm="appA" \
  master_admin_username="admin" \
  master_admin_password='<appA-admin-password>'

vault write keycloak-appB/config \
  url="https://keycloak-b.example.com" \
  realm="master" \
  target_realm="appB" \
  master_admin_username="admin" \
  master_admin_password='<appB-admin-password>'
```

## Expected logs

Check logs from the active Vault pod:

```bash
kubectl logs -n vault vault-0 --tail=200
```

Filter only plugin-relevant messages:

```bash
kubectl logs -n vault vault-0 --tail=500 \
  | grep -E 'keycloak|password rotated|failed to create Keycloak client|connection test failed|failed to initialise'
```

Operational/healthy examples:

- `keycloak secrets engine loaded successfully`
- `keycloak config saved and connection test succeeded`
- `password rotated successfully` with fields such as `role` and `keycloak_username`
- `kv secret updated successfully` with fields such as `kv_secret_path` and `kv_password_key`

Error examples:

- `keycloak secrets engine failed to initialise`
- `failed to create Keycloak client`
- `keycloak config saved but connection test failed`
- `failed to rotate password`
- `kv sync failed after password rotation`

## API reference

All paths below are relative to the mount point (default `keycloak/`).

### `config`

Configure the Keycloak backend. The plugin authenticates as an admin user
via the Resource Owner Password Credentials (ROPC) grant.

| Method | Vault CLI |
| --- | --- |
| Create / Update | `vault write keycloak/config ...` |
| Read | `vault read keycloak/config` |
| Delete | `vault delete keycloak/config` |

**Parameters:**

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `url` | string | yes | — | Base URL of the Keycloak server. |
| `realm` | string | no | `master` | Auth realm used to obtain admin tokens. |
| `target_realm` | string | no | value of `realm` | Realm whose users will be managed. |
| `client_id` | string | no | `admin-cli` | OIDC client used for the ROPC grant. |
| `master_admin_username` | string | yes | — | Username of the master realm admin. |
| `master_admin_password` | string | yes | — | Password of the master realm admin. |
| `kv_mount_path` | string | no | — | KV v2 mount name for KV sync after rotation. |
| `kv_secret_path` | string | no | — | Path within the KV v2 mount to PATCH. |
| `kv_api_addr` | string | no | `https://127.0.0.1:8200` | Vault API address for KV sync requests. |
| `kv_tls_skip_verify` | bool | no | `false` | Skip TLS verification for the KV API. |
| `kv_token` | string | no | — | Vault token with create/update/patch on the KV data path. |

### `roles/<name>`

Map a Vault role name to a Keycloak username. Used by the alpha
`creds/<name>` lease-based path.

| Method | Vault CLI |
| --- | --- |
| Create / Update | `vault write keycloak/roles/<name> ...` |
| Read | `vault read keycloak/roles/<name>` |
| Delete | `vault delete keycloak/roles/<name>` |
| List | `vault list keycloak/roles` |

**Parameters:**

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `name` | string | yes | — | Vault role name. |
| `keycloak_username` | string | yes | — | Keycloak username whose password will be rotated. |
| `ttl` | duration | no | `3600` (1 h) | Lease duration before automatic revocation. |
| `max_ttl` | duration | no | `86400` (24 h) | Maximum lease duration. |
| `kv_password_key` | string | no | — | KV v2 key to PATCH with the new password after rotation via `creds/<role>`. |

### `users/`

| Method | Vault CLI |
| --- | --- |
| List | `vault list keycloak/users` |

Returns the usernames of all users in the target realm (up to 500).

### `users/<username>`

| Method | Vault CLI |
| --- | --- |
| Read | `vault read keycloak/users/<username>` |

Returns the user's username, internal Keycloak ID, enabled status, email,
first name, and last name.

### `users/<username>/rotate`

| Method | Vault CLI |
| --- | --- |
| Update | `vault write -force keycloak/users/<username>/rotate` |

Generates a cryptographically random password (`crypto/rand`), sets it on
the Keycloak user via the Admin REST API, and returns `{ username, password }`.
The previous password is immediately invalidated. No lease is created.

**Optional parameter:**

| Parameter | Type | Required | Default | Description |
| --- | --- | --- | --- | --- |
| `kv_password_key` | string | no | — | KV v2 key to PATCH with the new password. Omit to skip KV sync. |

### `creds/<name>` (alpha)

| Method | Vault CLI |
| --- | --- |
| Read | `vault read keycloak/creds/<name>` |

Generates a password and sets it on the Keycloak user bound to `<name>`.
Returns `{ username, password }` with a Vault lease. On lease revocation the
password is rotated again to a discarded value, invalidating the issued
credential. On lease renewal the TTL is extended without rotation.

> **Alpha:** automatic lease expiry and revocation have not been fully
> validated end-to-end. See the [Credential lifecycle](#credential-lifecycle)
> section for caveats.

## Usage

List all users in the configured target realm:

```bash
vault list keycloak/users
```

Read a specific user's details:

```bash
vault read keycloak/users/<keycloak-username>
```

Rotate a user's password and return the new value:

```bash
vault write -force keycloak/users/<keycloak-username>/rotate
```

The command generates a cryptographically random password (`crypto/rand`),
sets it on the Keycloak account via the Admin REST API, and returns
`{ username, password }`. The previous password is immediately invalidated.
No lease is created; Vault retains no record of the issued credential.

## Credential lifecycle

The supported rotation path is fire-and-forget via
`vault write -force keycloak/users/<username>/rotate`.

The returned password remains valid in Keycloak indefinitely until the next
explicit rotation call. Vault retains no record of it and performs no
automatic revocation. Every call is recorded in the Vault audit log
(caller identity, mount path, timestamp).

> **Alpha — not recommended for production use yet:**
> The plugin also implements a role-based, lease-bound issuance path
> (`vault read keycloak/creds/<role>`) where Vault manages a TTL and
> automatically invalidates the credential on expiry by re-rotating the
> password to a discarded value. Automatic lease expiry and revocation
> have not been fully validated end-to-end and are considered alpha.
> See `path_credentials.go` in the source for implementation details.
>
> **Alpha caveat — Vault availability at revocation time:**
> Keycloak has no awareness of Vault leases. If Vault is unavailable when a
> lease TTL expires, the revocation callback is deferred and the issued
> password remains valid in Keycloak until Vault resumes. This is a known
> limitation of the alpha lease path and does not affect the supported
> fire-and-forget rotation path.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, testing, linting,
and the Conventional Commits guidelines used in this project.

## Security

To report a security vulnerability, please use
[GitHub Security Advisories](https://github.com/RoFz/vault-plugin-secrets-keycloak/security/advisories/new)
rather than a public issue. See [SECURITY.md](SECURITY.md) for the full policy.

## License

[Apache License 2.0](LICENSE)
