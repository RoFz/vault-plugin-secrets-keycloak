"""
Session-scoped fixtures: containers, clients, and shared test data.

Start order (all session scope):
  keycloak_container -> keycloak_url -> keycloak_realm (autouse)
  vault_container    -> vault_client  (registers plugin + enables KV)

All test modules receive these fixtures automatically. Test modules that need
the plugin configured against Keycloak define their own module-scoped
`plugin_configured` fixture that writes and cleans up the /config path.
"""

import hashlib
import os
from pathlib import Path

import hvac
import pytest
from keycloak import KeycloakAdmin, KeycloakOpenID, KeycloakOpenIDConnection
from testcontainers.keycloak import KeycloakContainer
from testcontainers.vault import VaultContainer

# ── Paths and images ──────────────────────────────────────────────────────────

# Built by `make build-test-binary`; sits two levels above this file.
PLUGIN_BINARY = Path(__file__).parents[2] / "bin" / "vault-plugin-secrets-keycloak"
PLUGIN_NAME = "vault-plugin-secrets-keycloak"
PLUGIN_MOUNT = "keycloak"

# Image versions are overridable via env so the CI matrix and `make` targets can
# pin specific Vault/Keycloak versions; defaults track the latest tested versions.
VAULT_VERSION = os.environ.get("VAULT_VERSION", "1.21.4")
VAULT_IMAGE = f"hashicorp/vault:{VAULT_VERSION}"
VAULT_ROOT_TOKEN = "root-token"

KEYCLOAK_VERSION = os.environ.get("KEYCLOAK_VERSION", "26.6.3")
KEYCLOAK_IMAGE = f"quay.io/keycloak/keycloak:{KEYCLOAK_VERSION}"
KEYCLOAK_ADMIN_USER = "admin"
KEYCLOAK_ADMIN_PASS = "admin"

# ── Test data ─────────────────────────────────────────────────────────────────

TEST_REALM = "test-realm"

# One dedicated Keycloak user per test scenario to prevent password collisions
# when multiple roles or rotations share the same user.
TEST_USER_EPHEMERAL = "vault-ephemeral-user"  # used by role and credential tests
TEST_USER_ROTATE = "vault-rotate-user"         # used by on-demand rotate tests

TEST_USER_INITIAL_PASS = "InitialPass123!"

# KV v2 mount used for KV-sync tests (enabled once by vault_client fixture).
KV_MOUNT = "kv-test"
KV_SECRET_PATH = "keycloak/passwords"


# ── Keycloak fixtures ─────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def keycloak_container():
    with (
        KeycloakContainer(
            KEYCLOAK_IMAGE,
            username=KEYCLOAK_ADMIN_USER,
            password=KEYCLOAK_ADMIN_PASS,
        )
        # Keycloak 26.3+ moves health endpoints to port 9000 (management
        # interface) by default. testcontainers probes port 9000 first; if
        # it gets a 404 during startup instead of a ConnectionError, the
        # retry loop aborts. Setting KC_HTTP_MANAGEMENT_HEALTH_ENABLED=false
        # keeps health on the main port (8080), so testcontainers falls back
        # there after failing to connect to port 9000.
        .with_env("KC_HTTP_MANAGEMENT_HEALTH_ENABLED", "false")
    ) as kc:
        yield kc


@pytest.fixture(scope="session")
def keycloak_url(keycloak_container):
    """Base URL of Keycloak reachable from the test runner (no trailing slash)."""
    return keycloak_container.get_url()


@pytest.fixture(scope="session", autouse=True)
def keycloak_realm(keycloak_container):
    """
    Create the test realm and all test users once for the whole session.

    autouse=True means this runs automatically for every test module without
    needing to be listed in each test's parameter list.
    """
    # Use master admin to create the test realm.
    master_admin = keycloak_container.get_client()
    master_admin.create_realm(
        payload={"realm": TEST_REALM, "enabled": True},
        skip_exists=True,
    )

    # Create a separate admin connection scoped to test-realm.
    # user_realm_name="master" means: authenticate the admin user against
    # master, but manage objects in TEST_REALM.
    keycloak_url = keycloak_container.get_url()
    connection = KeycloakOpenIDConnection(
        server_url=keycloak_url + "/",
        username=KEYCLOAK_ADMIN_USER,
        password=KEYCLOAK_ADMIN_PASS,
        realm_name=TEST_REALM,
        user_realm_name="master",
        verify=False,
    )
    admin = KeycloakAdmin(connection=connection)

    # Create a dedicated public OIDC client with direct access grants enabled.
    # This client is used by keycloak_auth_check to verify that rotated
    # passwords are actually valid in Keycloak via the ROPC grant.
    admin.create_client(
        payload={
            "clientId": "test-client",
            "publicClient": True,
            "directAccessGrantsEnabled": True,
            "enabled": True,
        },
        skip_exists=True,
    )

    for username in (TEST_USER_EPHEMERAL, TEST_USER_ROTATE):
        admin.create_user(
            payload={
                "username": username,
                "enabled": True,
                "emailVerified": True,
                "firstName": "Vault",
                "lastName": "Test",
                "email": f"{username}@test.local",
                "credentials": [
                    {
                        "type": "password",
                        "value": TEST_USER_INITIAL_PASS,
                        "temporary": False,
                    }
                ],
            },
            exist_ok=True,
        )

    return admin


# ── Vault fixtures ────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def vault_container():
    """
    Start a Vault dev container with the plugin binary mounted.

    The binary is mounted read-only at /vault/plugins/. VAULT_LOCAL_CONFIG
    tells Vault's dev server to treat that directory as the plugin directory
    and to advertise the correct api_addr so the plugin process can call back
    to Vault over gRPC.
    """
    assert PLUGIN_BINARY.exists(), (
        f"Plugin binary not found: {PLUGIN_BINARY}\n"
        "Run 'make build-test-binary' first."
    )

    container = (
        VaultContainer(
            VAULT_IMAGE,
            root_token=VAULT_ROOT_TOKEN,
            # On Linux (e.g. GitHub Actions), host.docker.internal is not set
            # automatically. extra_hosts maps it to the host gateway so the
            # plugin process can reach Keycloak on the Docker host.
            # On macOS Docker Desktop this is a no-op (already set).
            extra_hosts={"host.docker.internal": "host-gateway"},
        )
        .with_env("VAULT_LOCAL_CONFIG", '{"plugin_directory":"/vault/plugins","api_addr":"http://127.0.0.1:8200"}')
        .with_volume_mapping(str(PLUGIN_BINARY.parent), "/vault/plugins", "ro")
    )

    with container as vault:
        yield vault


@pytest.fixture(scope="session")
def vault_client(vault_container):
    """
    Return an authenticated hvac client and complete one-time Vault setup:
      - Register the plugin binary in the plugin catalog.
      - Enable the plugin at the 'keycloak' mount path.
      - Enable a KV v2 mount at 'kv-test' for KV-sync tests.
    """
    client = hvac.Client(
        url=vault_container.get_connection_url(),
        token=VAULT_ROOT_TOKEN,
    )
    assert client.is_authenticated(), "Vault root client failed to authenticate"

    sha256 = hashlib.sha256(PLUGIN_BINARY.read_bytes()).hexdigest()

    # hvac 2.x does not expose register_plugin; use the raw Vault API directly.
    # path is supplied positionally to avoid the hvac 2.x keyword-arg deprecation.
    client.write(
        f"sys/plugins/catalog/secret/{PLUGIN_NAME}",
        sha256=sha256,
        command=PLUGIN_NAME,
    )
    client.sys.enable_secrets_engine(
        backend_type=PLUGIN_NAME,
        path=PLUGIN_MOUNT,
    )

    # KV v2 mount used by KV-sync tests.
    client.sys.enable_secrets_engine(
        backend_type="kv",
        path=KV_MOUNT,
        options={"version": "2"},
    )

    return client


# ── Shared helpers ────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def plugin_config_params(keycloak_container):
    """
    Return the base dict of parameters needed to configure the plugin.

    The Keycloak URL uses host.docker.internal so the plugin process, which
    runs inside the Vault container, can reach Keycloak on the Docker host.
    On macOS Docker Desktop this hostname is configured automatically.
    On Linux (e.g. GitHub Actions) the vault_container fixture passes
    extra_hosts={"host.docker.internal": "host-gateway"} to the Docker run.

    Tests that want KV-sync fields should merge their own values on top.
    """
    port = keycloak_container.get_exposed_port(keycloak_container.port)
    internal_url = f"http://host.docker.internal:{port}"
    return {
        "url": internal_url,
        "realm": "master",
        "target_realm": TEST_REALM,
        "master_admin_username": KEYCLOAK_ADMIN_USER,
        "master_admin_password": KEYCLOAK_ADMIN_PASS,
    }


@pytest.fixture(scope="session")
def keycloak_auth_check(keycloak_url):
    """
    Return a callable that verifies whether (username, password) can obtain
    a token from the test realm via the ROPC grant. Use this to confirm that
    a password rotated by the plugin is actually valid in Keycloak.

    Usage: assert keycloak_auth_check("vault-static-user", returned_password)
    """

    def _check(username: str, password: str) -> bool:
        oidc = KeycloakOpenID(
            server_url=keycloak_url + "/",
            client_id="test-client",
            realm_name=TEST_REALM,
        )
        try:
            token = oidc.token(username=username, password=password)
            return bool(token.get("access_token"))
        except Exception:
            return False

    return _check
