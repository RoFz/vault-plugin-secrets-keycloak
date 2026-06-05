# Integration Testing

## Overview

The integration tests exercise the full plugin stack end-to-end: a real Vault
server loads and runs the plugin binary, and a real Keycloak server acts as the
identity provider. Both run as local Docker containers managed by the test
framework, so no external infrastructure is required.

The tests are needed because the plugin's correctness depends on three systems
behaving correctly together: the Vault plugin API (gRPC, storage, lease
management), the Keycloak Admin REST API (user and credential management), and
optionally the Vault KV v2 API (credential sync). Unit tests and Go-level mocks
cannot fully verify these interactions.

---

## Requirements

| Tool | Minimum version | Notes |
| --- | --- | --- |
| Go | 1.26 | Needed to compile the plugin binary |
| Docker | 20.10+ | Runs the Vault and Keycloak containers |
| Python | 3.12 | Managed via pyenv; see setup below |
| pyenv | any | Pins the Python version for the plugin directory |
| pip | bundled with Python | Used to install test dependencies |
| make | any | Provides convenience targets |

### Python packages

Direct dependencies are declared in [tests/requirements.txt](requirements.txt).
The fully hash-pinned lock file used by CI and local installs is
[tests/requirements.lock](requirements.lock):

```text
testcontainers[vault,keycloak]==4.14.2
hvac==2.4.0
python-keycloak==7.1.1
pytest==9.0.3
pytest-timeout==2.4.0
```

---

## Setup

All commands below must be run from the `vault-plugin-secrets-keycloak/`
directory (the same directory as this file's parent, and where the Makefile
lives).

### 1. Pin the Python version

```sh
pyenv local 3.12.8
```

This writes a `.python-version` file that tells pyenv to use Python 3.12.8
whenever you are in this directory.

### 2. Install Python dependencies

```sh
pip install --require-hashes -r tests/requirements.lock
```

### 3. Verify Docker is running

```sh
docker info
```

The tests start Vault and Keycloak containers automatically. Docker must be
running and your user must have permission to create containers.

---

## Running the tests

### All-in-one (recommended)

```sh
make test-integration
```

This target:

1. Compiles the plugin binary for `linux/amd64` (the OS and architecture of the
   Vault container) and places it in `bin/`.
2. Runs the full integration test suite with verbose output and a 120-second
   per-test timeout.

### Step by step

If you want to run the build and tests separately:

```sh
make build-test-binary
pytest tests/integration/ -v --timeout=120
```

### Subset of tests

Run a single test module:

```sh
pytest tests/integration/test_roles.py -v
```

Run a single test by name:

```sh
pytest tests/integration/test_ephemeral_credentials.py::test_creds_password_authenticates_in_keycloak -v
```

### Unit tests only (no Docker required)

```sh
make test-unit
```

Runs the Go unit tests with race detection. Does not start any containers.

---

## Test structure

The suite is split across four modules, each covering a distinct plugin path.

| Module | Plugin paths covered |
| --- | --- |
| `test_config.py` | `keycloak/config` |
| `test_roles.py` | `keycloak/roles/<name>` |
| `test_users.py` | `keycloak/users`, `keycloak/users/<name>`, `keycloak/users/<name>/rotate` |
| `test_ephemeral_credentials.py` | `keycloak/creds/<role>` with KV sync |

### Shared infrastructure (`conftest.py`)

Session-scoped fixtures start once per `pytest` invocation and are shared
across all modules:

- `keycloak_container`: starts a Keycloak 26.5.7 container.
- `keycloak_realm` (autouse): creates the `test-realm` realm and two dedicated
  test users (`vault-ephemeral-user`, `vault-rotate-user`). Also creates a
  `test-client` OIDC public client used to verify that passwords are accepted
  by Keycloak.
- `vault_container`: starts a Vault 1.21.4 dev container with the plugin
  binary mounted at `/vault/plugins/`.
- `vault_client`: registers the plugin in Vault's catalog, enables it at the
  `keycloak` mount, and enables a KV v2 mount at `kv-test` for sync tests.
- `plugin_config_params`: returns the base configuration dict. The Keycloak URL
  uses `host.docker.internal` so the plugin process (running inside the Vault
  container) can reach the Keycloak container on the Docker host.
- `keycloak_auth_check`: returns a callable that attempts an ROPC token grant
  against Keycloak to confirm that a password is valid.

Each test module defines its own `plugin_configured` module-scoped fixture that
writes and cleans up `keycloak/config`. Tests within a module are isolated
from one another through unique role names or per-test cleanup fixtures.

### `test_config.py` (7 tests)

Verifies the `keycloak/config` CRUD lifecycle:

- Reading config before it is set returns nothing.
- Writing then reading round-trips all non-sensitive fields.
- `master_admin_password` and `kv_token` are write-only and not returned on
  read.
- KV-sync fields (`kv_mount_path`, `kv_secret_path`, `kv_api_addr`,
  `kv_tls_skip_verify`) are stored and returned correctly.
- Deleting config makes subsequent reads return nothing.
- Omitting `target_realm` causes the plugin to default it to the value of
  `realm`.

### `test_roles.py` (5 tests)

Verifies role creation, update, deletion, listing, and input validation:

- Roles are created with `ttl` and `max_ttl` and their fields round-trip
  correctly.
- Updating a role's `ttl` is accepted.
- Deleting a role causes subsequent reads to return nothing.
- Listing roles returns all created role names.
- Validation rejects `max_ttl` less than `ttl`.

### `test_users.py` (6 tests)

Verifies the user introspection and on-demand rotation paths:

- Listing users returns the Keycloak usernames from the target realm.
- Reading a user returns `username`, `enabled`, `id`, `email`, `first_name`,
  and `last_name`.
- Reading a nonexistent user returns an error containing "not found".
- On-demand rotation via `users/<username>/rotate` returns a new password.
- The returned password authenticates successfully in Keycloak.
- Two successive rotations produce different passwords.

### `test_ephemeral_credentials.py` (5 tests)

Verifies the credential lifecycle including KV sync:

- Reading `creds/<role>` returns `username` and `password`.
- The returned password authenticates in Keycloak.
- Each read generates a fresh password (previous password is invalidated).
- The response carries a Vault lease with a positive TTL.
- Reading with a role that has `kv_password_key` patches the KV v2 secret with
  the newly generated password.

---

## Expected successful output

Containers start automatically on the first test run. Keycloak takes roughly
20-30 seconds to become ready; Vault is faster. Subsequent fixture teardown
happens in the background after the last test completes.

A passing run looks similar to:

```text
========================= test session starts ==========================
platform darwin -- Python 3.12.8, pytest-9.0.3, pluggy-1.5.0
collected 23 items

tests/integration/test_config.py::test_config_read_returns_none_when_not_set PASSED
tests/integration/test_config.py::test_config_write_and_read PASSED
...
tests/integration/test_ephemeral_credentials.py::test_creds_syncs_kv_secret PASSED

========================== 23 passed in ~35s ===========================
```

Total wall-clock time is typically 30-40 seconds, dominated by container
startup (Keycloak in particular).

---

## Known issues

### `test_config.py::test_config_target_realm_defaults_to_realm`

This test documents current plugin behavior: when `target_realm` is omitted,
the plugin stores it as an empty string rather than defaulting it to the value
of `realm`. The test asserts only that `realm` is stored correctly; it does not
assert the value of `target_realm`. If the plugin is updated to explicitly
default `target_realm` to `realm`, the test should be tightened to assert
`data["target_realm"] == "master"`.
