# Vault Keycloak Secrets Engine

Custom Vault secrets engine plugin that rotates Keycloak realm user passwords.

## What this plugin does

This plugin mounts as a Vault secrets engine and provides endpoints to:

- Configure Keycloak admin access.
- List and read users in the target realm.
- Rotate a user password on demand and return the new value.

## Plugin process flow

```mermaid
flowchart TD
  A[Operator calls Vault path] --> B{Path}
  B -->|keycloak/config| C[Store config in Vault storage]
  C --> D[Test Keycloak connection via admin token]
  B -->|keycloak/role/name| E[Store role -> keycloak_username mapping]
  B -->|keycloak/creds/role| F[Load role and config]
  F --> G[Generate random password]
  G --> H[Call Keycloak Admin API reset-password]
  H --> I[Return username and new password]
  B -->|keycloak/users| J[List users in target realm]
  B -->|keycloak/users/username| K[Read user details]
  B -->|keycloak/users/username/rotate| L[Generate password + reset in Keycloak]
  L --> M[Return username and new password]
```

## Requirements

- Access to a running Vault pod.
- Vault token with permission to register and enable plugins.
- Keycloak admin credentials for the configured realm.
- A writable plugin directory mounted in Vault at `/vault/plugins`.

### FluxCD method (recommended, and how this was deployed)

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

## Build and copy to Vault pod

Build a Linux plugin binary:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o vault-plugin-secrets-keycloak ./cmd/vault-plugin-secrets-keycloak
```

Copy binary to the active Vault pod:

```bash
kubectl cp ./vault-plugin-secrets-keycloak vault/vault-0:/vault/plugins/vault-plugin-secrets-keycloak
kubectl exec -n vault vault-0 -- chmod 0755 /vault/plugins/vault-plugin-secrets-keycloak
```

Compute SHA256 from inside the pod (used for plugin registration):

```bash
kubectl exec -n vault vault-0 -- sha256sum /vault/plugins/vault-plugin-secrets-keycloak
```

## Enable and configure in Vault

Register and enable the plugin:

```bash
SHA256=$(kubectl exec -n vault vault-0 -- sha256sum /vault/plugins/vault-plugin-secrets-keycloak | cut -d' ' -f1)

vault plugin register -sha256="$SHA256" secret vault-plugin-secrets-keycloak
vault secrets enable -path=keycloak vault-plugin-secrets-keycloak
```

Write plugin configuration:

```bash
vault write keycloak/config \
  url="https://keycloak.example.com" \
  realm="master" \
  target_realm="myrealm" \
  username="admin" \
  password='<admin-password>'
```

Configure additional Keycloak deployments/realms:

- The plugin stores one config per mount (`<mount>/config`).
- To manage multiple Keycloak contexts, enable the plugin at multiple mount paths.

Example with two independent mounts:

```bash
vault secrets enable -path=keycloak-appA vault-plugin-secrets-keycloak
vault secrets enable -path=keycloak-appB vault-plugin-secrets-keycloak

vault write keycloak-appA/config \
  url="https://keycloak.example.com" \
  realm="master" \
  target_realm="myrealm" \
  username="admin" \
  password='appA-admin-password'

vault write keycloak-appB/config \
  url="https://keycloak-b.example.com" \
  realm="master" \
  target_realm="appB" \
  username="admin" \
  password='appB-admin-password'
```

Script example to configure any mount/context:

```bash
configure_keycloak_mount() {
  local mount_path="$1"
  local url="$2"
  local realm="$3"
  local target_realm="$4"
  local username="$5"
  local password="$6"

  vault secrets enable -path="$mount_path" vault-plugin-secrets-keycloak 2>/dev/null || true
  vault write "$mount_path/config" \
    url="$url" \
    realm="$realm" \
    target_realm="$target_realm" \
    username="$username" \
    password="$password"
}

configure_keycloak_mount keycloak-appA "https://keycloak.example.com" master myrealm admin 'appA-admin-password'
configure_keycloak_mount keycloak-appB "https://keycloak-b.example.com" master appB admin 'appB-admin-password'
```

## Expected logs (health checks)

Check logs from the active Vault pod:

```bash
kubectl logs -n vault vault-0 --tail=200
```

Filter only plugin-relevant messages:

```bash
kubectl logs -n vault vault-0 --tail=500 | rg 'keycloak|password rotated|failed to create Keycloak client|connection test failed|failed to initialise'
```

If `rg` is not available locally, use grep:

```bash
kubectl logs -n vault vault-0 --tail=500 | grep -E 'keycloak|password rotated|failed to create Keycloak client|connection test failed|failed to initialise'
```

Operational/healthy examples:

- `keycloak secrets engine loaded successfully`
- `keycloak config saved and connection test succeeded`
- `password rotated successfully` with fields such as `role` and `keycloak_username`

Error examples:

- `keycloak secrets engine failed to initialise`
- `failed to create Keycloak client`
- `keycloak config saved but connection test failed`
- `failed to rotate password`

## Rotate a Keycloak user password with Vault CLI

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
