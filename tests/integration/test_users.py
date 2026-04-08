"""
Tests for the keycloak/users paths.

  LIST   keycloak/users
  READ   keycloak/users/<username>
  WRITE  keycloak/users/<username>/rotate  (on-demand rotation)

The plugin must be configured before any of these paths are usable. A
module-scoped fixture writes the config once and cleans it up after the module.
"""

import hvac.exceptions
import pytest

from conftest import (
    PLUGIN_MOUNT,
    TEST_REALM,
    TEST_USER_EPHEMERAL,
    TEST_USER_ROTATE,
)


# ── Module fixtures ───────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def plugin_configured(vault_client, plugin_config_params):
    vault_client.write(f"{PLUGIN_MOUNT}/config", **plugin_config_params)
    yield
    vault_client.delete(f"{PLUGIN_MOUNT}/config")


# ── List users ────────────────────────────────────────────────────────────────

def test_list_users_returns_test_users(vault_client, plugin_configured):
    response = vault_client.list(f"{PLUGIN_MOUNT}/users")
    usernames = response["data"]["keys"]

    assert TEST_USER_EPHEMERAL in usernames
    assert TEST_USER_ROTATE in usernames


# ── Read user ─────────────────────────────────────────────────────────────────

def test_read_user_returns_expected_fields(vault_client, plugin_configured):
    response = vault_client.read(f"{PLUGIN_MOUNT}/users/{TEST_USER_EPHEMERAL}")
    data = response["data"]

    assert data["username"] == TEST_USER_EPHEMERAL
    assert data["enabled"] is True
    assert "id" in data
    assert "email" in data
    assert "first_name" in data
    assert "last_name" in data


def test_read_nonexistent_user_returns_error(vault_client, plugin_configured):
    with pytest.raises(hvac.exceptions.InvalidRequest) as exc:
        vault_client.read(f"{PLUGIN_MOUNT}/users/no-such-user-xyz")
    assert "not found" in str(exc.value)


# ── On-demand rotate ──────────────────────────────────────────────────────────

def test_on_demand_rotate_returns_new_password(vault_client, plugin_configured):
    response = vault_client.write(f"{PLUGIN_MOUNT}/users/{TEST_USER_ROTATE}/rotate")
    data = response["data"]

    assert data["username"] == TEST_USER_ROTATE
    assert isinstance(data["password"], str)
    assert len(data["password"]) > 0


def test_on_demand_rotate_password_authenticates_in_keycloak(
    vault_client, plugin_configured, keycloak_auth_check
):
    response = vault_client.write(f"{PLUGIN_MOUNT}/users/{TEST_USER_ROTATE}/rotate")
    new_password = response["data"]["password"]

    assert keycloak_auth_check(TEST_USER_ROTATE, new_password), (
        f"Rotated password for {TEST_USER_ROTATE} did not authenticate in "
        f"realm '{TEST_REALM}'"
    )


def test_on_demand_rotate_twice_produces_different_passwords(
    vault_client, plugin_configured
):
    r1 = vault_client.write(f"{PLUGIN_MOUNT}/users/{TEST_USER_ROTATE}/rotate")
    r2 = vault_client.write(f"{PLUGIN_MOUNT}/users/{TEST_USER_ROTATE}/rotate")

    assert r1["data"]["password"] != r2["data"]["password"]
