"""
Tests for the credential workflow.

Realistic sequence (mirrors actual Vault deployment usage):
  1. Configure the plugin (with KV-sync fields for KV tests).
  2. Create a role for TEST_USER_EPHEMERAL.
     No Keycloak call happens until the first creds/<role> read.
  3. Read creds/<role>: Vault generates a password, sets it on Keycloak, and
     returns it with a lease. Each read generates a fresh password.
  4. Verify the returned password authenticates in Keycloak.
  5. Verify that each read produces a different password.
  6. Verify KV-sync on a role with kv_password_key.
"""

import pytest

from conftest import (
    KV_MOUNT,
    KV_SECRET_PATH,
    PLUGIN_MOUNT,
    TEST_REALM,
    TEST_USER_EPHEMERAL,
    VAULT_ROOT_TOKEN,
)

CREDS_ROLE = "creds-main"
KV_PASSWORD_KEY = "ephemeral_user_password"


# ── Module fixtures ───────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def plugin_configured(vault_client, plugin_config_params):
    """Configure the plugin with KV-sync fields for this module."""
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
def creds_role(vault_client, plugin_configured):
    """
    Create the role used by all tests in this module.

    No rotation occurs at creation time -- the first rotation happens on the
    first creds/<role> read.
    """
    vault_client.write(
        f"{PLUGIN_MOUNT}/roles/{CREDS_ROLE}",
        keycloak_username=TEST_USER_EPHEMERAL,
        ttl="5m",
        max_ttl="10m",
        kv_password_key=KV_PASSWORD_KEY,
    )
    yield CREDS_ROLE
    vault_client.delete(f"{PLUGIN_MOUNT}/roles/{CREDS_ROLE}")


# ── Read creds ────────────────────────────────────────────────────────────────

def test_creds_returns_expected_fields(vault_client, creds_role):
    data = vault_client.read(f"{PLUGIN_MOUNT}/creds/{creds_role}")["data"]

    assert data["username"] == TEST_USER_EPHEMERAL
    assert isinstance(data["password"], str)
    assert len(data["password"]) > 0


def test_creds_password_authenticates_in_keycloak(
    vault_client, creds_role, keycloak_auth_check
):
    password = vault_client.read(
        f"{PLUGIN_MOUNT}/creds/{creds_role}"
    )["data"]["password"]

    assert keycloak_auth_check(TEST_USER_EPHEMERAL, password), (
        f"Password from creds/{creds_role} did not authenticate "
        f"user '{TEST_USER_EPHEMERAL}' in realm '{TEST_REALM}'"
    )


def test_each_read_returns_different_password(vault_client, creds_role):
    """
    Every creds/<role> read must produce a unique password. The previous
    password is no longer valid in Keycloak after the next read because each
    read resets the Keycloak user's password.
    """
    p1 = vault_client.read(f"{PLUGIN_MOUNT}/creds/{creds_role}")["data"]["password"]
    p2 = vault_client.read(f"{PLUGIN_MOUNT}/creds/{creds_role}")["data"]["password"]
    assert p1 != p2


def test_creds_lease_has_ttl(vault_client, creds_role):
    """The response must carry a Vault lease with a positive TTL."""
    response = vault_client.read(f"{PLUGIN_MOUNT}/creds/{creds_role}")

    lease_duration = response.get("lease_duration") or 0
    assert lease_duration > 0
    assert response.get("lease_id")


# ── KV-sync on creds read ─────────────────────────────────────────────────────

def test_creds_syncs_kv_secret(vault_client, creds_role):
    """
    Reading creds/<role> for a role with kv_password_key must patch the KV
    secret with the newly generated password.
    """
    response = vault_client.read(f"{PLUGIN_MOUNT}/creds/{creds_role}")
    expected_password = response["data"]["password"]

    kv_data = vault_client.secrets.kv.v2.read_secret_version(
        path=KV_SECRET_PATH,
        mount_point=KV_MOUNT,
        raise_on_deleted_version=True,
    )["data"]["data"]

    assert kv_data.get(KV_PASSWORD_KEY) == expected_password
