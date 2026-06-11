"""
Tests for the static credential workflow.

Realistic sequence (mirrors actual Vault deployment usage):
  1. Configure the plugin (with KV-sync fields so KV tests work).
  2. Create a static role for TEST_USER_STATIC with a kv_password_key.
     Creating the role triggers an immediate first rotation — the user's
     password is now managed by Vault and stored in static-creds/<role>.
  3. Read static-creds/<role> to retrieve the current password.
  4. Verify the password authenticates in Keycloak.
  5. Call users/<username>/rotate (on-demand) to rotate and verify KV sync.
  6. Verify the cross-path error: ephemeral roles must not be read via
     static-creds/, and vice versa.

The plugin config and the static role are module-scoped fixtures — created
once and shared across all tests in this file.
"""

import hvac.exceptions
import pytest

from conftest import (
    KV_MOUNT,
    KV_SECRET_PATH,
    PLUGIN_MOUNT,
    TEST_REALM,
    TEST_USER_EPHEMERAL,
    TEST_USER_STATIC,
    VAULT_ROOT_TOKEN,
)

STATIC_ROLE = "static-main"
KV_PASSWORD_KEY = "static_user_password"


# ── Module fixtures ───────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def plugin_configured(vault_client, plugin_config_params):
    """
    Configure the plugin with KV-sync fields so that roles created in this
    module can exercise the KV-sync path.

    kv_api_addr points to Vault's internal address because the plugin process
    runs inside the Vault container and calls back to Vault over loopback.
    kv_tls_skip_verify is True because the dev server uses plain HTTP (the
    TLS skip is a no-op here but documents the field's purpose).
    kv_token uses the root token for simplicity — in production use a scoped
    service token.
    """
    config = {
        **plugin_config_params,
        "kv_mount_path": KV_MOUNT,
        "kv_secret_path": KV_SECRET_PATH,
        "kv_api_addr": "http://127.0.0.1:8200",
        "kv_tls_skip_verify": True,
        "kv_token": VAULT_ROOT_TOKEN,
    }
    vault_client.write(f"{PLUGIN_MOUNT}/config", **config)
    yield
    vault_client.delete(f"{PLUGIN_MOUNT}/config")


@pytest.fixture(scope="module")
def static_role(vault_client, plugin_configured):
    """
    Create the static role used by all tests in this module.

    Creating the role triggers the initial rotation: Vault generates a
    password, sets it on Keycloak, and stores it in static-creds/static-main.
    The kv_password_key wires KV-sync so that every subsequent rotation also
    patches the KV secret.
    """
    vault_client.write(
        f"{PLUGIN_MOUNT}/roles/{STATIC_ROLE}",
        keycloak_username=TEST_USER_STATIC,
        rotation_period="30m",
        kv_password_key=KV_PASSWORD_KEY,
    )
    yield STATIC_ROLE
    vault_client.delete(f"{PLUGIN_MOUNT}/roles/{STATIC_ROLE}")


# ── Read static-creds ─────────────────────────────────────────────────────────

def test_static_creds_returns_expected_fields(vault_client, static_role):
    data = vault_client.read(f"{PLUGIN_MOUNT}/static-creds/{static_role}")["data"]

    assert data["username"] == TEST_USER_STATIC
    assert isinstance(data["password"], str)
    assert len(data["password"]) > 0
    assert "last_rotation" in data
    assert data["rotation_period"] == 1800.0  # 30m in seconds
    assert "next_rotation" in data
    assert data["kv_synced"] is True  # KV sync is configured and must have landed


def test_static_creds_password_authenticates_in_keycloak(
    vault_client, static_role, keycloak_auth_check
):
    password = vault_client.read(
        f"{PLUGIN_MOUNT}/static-creds/{static_role}"
    )["data"]["password"]

    assert keycloak_auth_check(TEST_USER_STATIC, password), (
        f"Password from static-creds/{static_role} did not authenticate "
        f"user '{TEST_USER_STATIC}' in realm '{TEST_REALM}'"
    )


def test_static_creds_repeated_reads_return_same_password(vault_client, static_role):
    # Static credentials are stable between rotations — reads must be idempotent.
    p1 = vault_client.read(f"{PLUGIN_MOUNT}/static-creds/{static_role}")["data"]["password"]
    p2 = vault_client.read(f"{PLUGIN_MOUNT}/static-creds/{static_role}")["data"]["password"]
    assert p1 == p2


# ── On-demand rotate (users/<username>/rotate) ────────────────────────────────

def test_manual_rotate_changes_password(vault_client, static_role):
    before = vault_client.read(
        f"{PLUGIN_MOUNT}/static-creds/{static_role}"
    )["data"]["password"]

    vault_client.write(f"{PLUGIN_MOUNT}/users/{TEST_USER_STATIC}/rotate")

    after = vault_client.read(
        f"{PLUGIN_MOUNT}/static-creds/{static_role}"
    )["data"]["password"]

    assert before != after


def test_manual_rotate_new_password_authenticates_in_keycloak(
    vault_client, static_role, keycloak_auth_check
):
    response = vault_client.write(f"{PLUGIN_MOUNT}/users/{TEST_USER_STATIC}/rotate")
    new_password = response["data"]["password"]

    assert keycloak_auth_check(TEST_USER_STATIC, new_password), (
        f"Password returned by users/{TEST_USER_STATIC}/rotate did not "
        f"authenticate in realm '{TEST_REALM}'"
    )


def test_manual_rotate_syncs_kv_secret(vault_client, static_role):
    """
    After a manual rotate with kv_password_key, the KV v2 secret must contain
    the new password under the configured key.
    """
    response = vault_client.write(
        f"{PLUGIN_MOUNT}/users/{TEST_USER_STATIC}/rotate",
        kv_password_key=KV_PASSWORD_KEY,
    )
    expected_password = response["data"]["password"]

    kv_data = vault_client.secrets.kv.v2.read_secret_version(
        path=KV_SECRET_PATH,
        mount_point=KV_MOUNT,
        raise_on_deleted_version=True,
    )["data"]["data"]

    assert kv_data.get(KV_PASSWORD_KEY) == expected_password


def test_manual_rotate_resets_autorotation_timer(vault_client, static_role):
    """
    After users/<username>/rotate, static-creds/<role> must reflect the new
    password (the autorotation timer has been reset and the stored cred synced).
    """
    rotate_response = vault_client.write(
        f"{PLUGIN_MOUNT}/users/{TEST_USER_STATIC}/rotate"
    )
    rotated_password = rotate_response["data"]["password"]

    stored_password = vault_client.read(
        f"{PLUGIN_MOUNT}/static-creds/{static_role}"
    )["data"]["password"]

    assert stored_password == rotated_password


# ── Cross-path errors ─────────────────────────────────────────────────────────

def test_static_creds_on_ephemeral_role_returns_error(vault_client, plugin_configured):
    ephemeral_role = "tmp-ephemeral-for-static-test"
    vault_client.write(
        f"{PLUGIN_MOUNT}/roles/{ephemeral_role}",
        keycloak_username=TEST_USER_EPHEMERAL,
        ephemeral=True,
        ttl="1m",
        max_ttl="2m",
    )
    try:
        with pytest.raises(hvac.exceptions.InvalidRequest) as exc:
            vault_client.read(f"{PLUGIN_MOUNT}/static-creds/{ephemeral_role}")
        assert "ephemeral" in str(exc.value)
    finally:
        vault_client.delete(f"{PLUGIN_MOUNT}/roles/{ephemeral_role}")


def test_username_exclusivity_rejects_second_role(vault_client, static_role):
    """
    The static role maps TEST_USER_STATIC; any other role (static or
    ephemeral) on the same username must be rejected.
    """
    with pytest.raises(hvac.exceptions.InvalidRequest) as exc:
        vault_client.write(
            f"{PLUGIN_MOUNT}/roles/tmp-conflicting-role",
            keycloak_username=TEST_USER_STATIC,
            ephemeral=True,
            ttl="1m",
            max_ttl="2m",
        )
    assert "already mapped" in str(exc.value)
