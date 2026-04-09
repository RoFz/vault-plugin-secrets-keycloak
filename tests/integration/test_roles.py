"""
Tests for the keycloak/roles path.

In v0.2.x all roles are credential-generating roles (no static vs ephemeral
distinction). Each role maps a Vault role name to a Keycloak username and
carries a ttl, max_ttl, and optional kv_password_key.

Each test function creates the role(s) it needs and cleans them up via a yield
fixture, so tests are independent and can run in any order.
"""

import uuid

import hvac.exceptions
import pytest

from conftest import (
    PLUGIN_MOUNT,
    TEST_USER_EPHEMERAL,
)


# ── Module fixtures ───────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def plugin_configured(vault_client, plugin_config_params):
    """Write the plugin config for this module and remove it when done."""
    vault_client.write(f"{PLUGIN_MOUNT}/config", **plugin_config_params)
    yield
    vault_client.delete(f"{PLUGIN_MOUNT}/config")


@pytest.fixture
def role_name():
    """Generate a unique role name so tests never collide."""
    return f"test-role-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def role(vault_client, plugin_configured, role_name):
    """Create a minimal role and delete it after the test."""
    vault_client.write(
        f"{PLUGIN_MOUNT}/roles/{role_name}",
        keycloak_username=TEST_USER_EPHEMERAL,
        ttl="1h",
        max_ttl="2h",
    )
    yield role_name
    vault_client.delete(f"{PLUGIN_MOUNT}/roles/{role_name}")


# ── CRUD tests ────────────────────────────────────────────────────────────────

def test_create_and_read_role(role, vault_client):
    data = vault_client.read(f"{PLUGIN_MOUNT}/roles/{role}")["data"]
    assert data["keycloak_username"] == TEST_USER_EPHEMERAL
    assert data["ttl"] == 3600.0    # 1h in seconds
    assert data["max_ttl"] == 7200.0  # 2h in seconds


def test_role_update(role, vault_client):
    vault_client.write(
        f"{PLUGIN_MOUNT}/roles/{role}",
        keycloak_username=TEST_USER_EPHEMERAL,
        ttl="30m",
    )
    data = vault_client.read(f"{PLUGIN_MOUNT}/roles/{role}")["data"]
    assert data["ttl"] == 1800.0  # 30m in seconds


def test_delete_role(vault_client, plugin_configured, role_name):
    vault_client.write(
        f"{PLUGIN_MOUNT}/roles/{role_name}",
        keycloak_username=TEST_USER_EPHEMERAL,
        ttl="1h",
    )
    vault_client.delete(f"{PLUGIN_MOUNT}/roles/{role_name}")
    response = vault_client.read(f"{PLUGIN_MOUNT}/roles/{role_name}")
    assert response is None


# ── List roles ────────────────────────────────────────────────────────────────

def test_list_roles(vault_client, plugin_configured):
    names = [f"list-role-{uuid.uuid4().hex[:6]}" for _ in range(3)]
    try:
        for name in names:
            vault_client.write(
                f"{PLUGIN_MOUNT}/roles/{name}",
                keycloak_username=TEST_USER_EPHEMERAL,
                ttl="1h",
                max_ttl="2h",
            )

        response = vault_client.list(f"{PLUGIN_MOUNT}/roles")
        listed = response["data"]["keys"]
        for name in names:
            assert name in listed
    finally:
        for name in names:
            vault_client.delete(f"{PLUGIN_MOUNT}/roles/{name}")


# ── Validation tests ──────────────────────────────────────────────────────────

def test_role_max_ttl_must_be_gte_ttl(vault_client, plugin_configured, role_name):
    with pytest.raises(hvac.exceptions.InvalidRequest) as exc:
        vault_client.write(
            f"{PLUGIN_MOUNT}/roles/{role_name}",
            keycloak_username=TEST_USER_EPHEMERAL,
            ttl="2h",
            max_ttl="1h",  # less than ttl
        )
    assert "max_ttl" in str(exc.value)
