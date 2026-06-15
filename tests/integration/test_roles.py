"""
Tests for the keycloak/roles path.

Workflow mirrors real usage: configure the plugin first, then create roles.

Creating a static (non-ephemeral) role triggers an immediate first rotation
against Keycloak, so the plugin must be configured and Keycloak must be
reachable before any static role is created. The module-scoped
`plugin_configured` fixture handles this.

Each test function creates the role(s) it needs and cleans them up via a yield
fixture, so tests are independent and can run in any order.
"""

import uuid

import hvac.exceptions
import pytest

from conftest import (
    PLUGIN_MOUNT,
    TEST_USER_STATIC,
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
def static_role(vault_client, plugin_configured, role_name):
    """Create a minimal static role and delete it after the test."""
    vault_client.write(
        f"{PLUGIN_MOUNT}/roles/{role_name}",
        keycloak_username=TEST_USER_STATIC,
        rotation_period="30m",  # minimum allowed
    )
    yield role_name
    vault_client.delete(f"{PLUGIN_MOUNT}/roles/{role_name}")


@pytest.fixture
def ephemeral_role(vault_client, plugin_configured, role_name):
    """Create a minimal ephemeral role and delete it after the test."""
    vault_client.write(
        f"{PLUGIN_MOUNT}/roles/{role_name}",
        keycloak_username=TEST_USER_STATIC,
        ephemeral=True,
        ttl="1m",
        max_ttl="2m",
    )
    yield role_name
    vault_client.delete(f"{PLUGIN_MOUNT}/roles/{role_name}")


# ── Static role tests ─────────────────────────────────────────────────────────

def test_create_and_read_static_role(static_role, vault_client):
    data = vault_client.read(f"{PLUGIN_MOUNT}/roles/{static_role}")["data"]
    assert data["keycloak_username"] == TEST_USER_STATIC
    assert data["ephemeral"] is False
    assert data["rotation_period"] == 1800  # 30m in seconds


def test_static_role_update(static_role, vault_client):
    # Update the rotation period — plugin should accept it without re-rotating.
    vault_client.write(
        f"{PLUGIN_MOUNT}/roles/{static_role}",
        keycloak_username=TEST_USER_STATIC,
        rotation_period="1h",
    )
    data = vault_client.read(f"{PLUGIN_MOUNT}/roles/{static_role}")["data"]
    assert data["rotation_period"] == 3600  # 1h in seconds


def test_delete_static_role(vault_client, plugin_configured, role_name):
    vault_client.write(
        f"{PLUGIN_MOUNT}/roles/{role_name}",
        keycloak_username=TEST_USER_STATIC,
        rotation_period="1800",
    )
    vault_client.delete(f"{PLUGIN_MOUNT}/roles/{role_name}")
    response = vault_client.read(f"{PLUGIN_MOUNT}/roles/{role_name}")
    assert response is None


# ── Ephemeral role tests ──────────────────────────────────────────────────────

def test_create_and_read_ephemeral_role(ephemeral_role, vault_client):
    data = vault_client.read(f"{PLUGIN_MOUNT}/roles/{ephemeral_role}")["data"]
    assert data["keycloak_username"] == TEST_USER_STATIC
    assert data["ephemeral"] is True
    assert data["ttl"] == 60     # 1m in seconds
    assert data["max_ttl"] == 120  # 2m in seconds


# ── List roles ────────────────────────────────────────────────────────────────

def test_list_roles(vault_client, plugin_configured):
    names = [f"list-role-{uuid.uuid4().hex[:6]}" for _ in range(3)]
    try:
        for name in names:
            vault_client.write(
                f"{PLUGIN_MOUNT}/roles/{name}",
                keycloak_username=TEST_USER_STATIC,
                ephemeral=True,
                ttl="1m",
                max_ttl="2m",
            )

        response = vault_client.list(f"{PLUGIN_MOUNT}/roles")
        listed = response["data"]["keys"]
        for name in names:
            assert name in listed
    finally:
        for name in names:
            vault_client.delete(f"{PLUGIN_MOUNT}/roles/{name}")


# ── Validation tests (no Keycloak call needed — errors returned before it) ───

def test_static_role_rejects_ttl(vault_client, plugin_configured, role_name):
    with pytest.raises(hvac.exceptions.InvalidRequest) as exc:
        vault_client.write(
            f"{PLUGIN_MOUNT}/roles/{role_name}",
            keycloak_username=TEST_USER_STATIC,
            rotation_period="30m",
            ttl="1m",  # not allowed for static roles
        )
    assert "ttl" in str(exc.value)


def test_static_role_rejects_max_ttl(vault_client, plugin_configured, role_name):
    with pytest.raises(hvac.exceptions.InvalidRequest) as exc:
        vault_client.write(
            f"{PLUGIN_MOUNT}/roles/{role_name}",
            keycloak_username=TEST_USER_STATIC,
            rotation_period="30m",
            max_ttl="2m",  # not allowed for static roles
        )
    assert "max_ttl" in str(exc.value)


def test_ephemeral_role_rejects_rotation_period(vault_client, plugin_configured, role_name):
    with pytest.raises(hvac.exceptions.InvalidRequest) as exc:
        vault_client.write(
            f"{PLUGIN_MOUNT}/roles/{role_name}",
            keycloak_username=TEST_USER_STATIC,
            ephemeral=True,
            ttl="1m",
            max_ttl="2m",
            rotation_period="30m",  # not allowed for ephemeral roles
        )
    assert "rotation_period" in str(exc.value)


def test_ephemeral_role_requires_min_ttl(vault_client, plugin_configured, role_name):
    with pytest.raises(hvac.exceptions.InvalidRequest) as exc:
        vault_client.write(
            f"{PLUGIN_MOUNT}/roles/{role_name}",
            keycloak_username=TEST_USER_STATIC,
            ephemeral=True,
            ttl="30s",  # below minimum 1m
            max_ttl="2m",
        )
    assert "ttl" in str(exc.value)


def test_static_role_requires_min_rotation_period(vault_client, plugin_configured, role_name):
    with pytest.raises(hvac.exceptions.InvalidRequest) as exc:
        vault_client.write(
            f"{PLUGIN_MOUNT}/roles/{role_name}",
            keycloak_username=TEST_USER_STATIC,
            rotation_period="1m",  # below minimum 30m
        )
    assert "rotation_period" in str(exc.value)


def test_ephemeral_role_max_ttl_must_be_gte_ttl(vault_client, plugin_configured, role_name):
    with pytest.raises(hvac.exceptions.InvalidRequest) as exc:
        vault_client.write(
            f"{PLUGIN_MOUNT}/roles/{role_name}",
            keycloak_username=TEST_USER_STATIC,
            ephemeral=True,
            ttl="2m",
            max_ttl="1m",  # less than ttl
        )
    assert "max_ttl" in str(exc.value)


# ── Mode conversion ───────────────────────────────────────────────────────────

def test_mode_conversion_round_trip(vault_client, plugin_configured, role_name, keycloak_auth_check):
    """
    static -> ephemeral -> static. Converting to ephemeral stops managing the
    credential (the live password keeps working: continuity-first design) and
    clears the stored entry; converting back rotates immediately so
    static-creds serves a fresh, working credential.
    """
    from conftest import TEST_USER_STATIC

    vault_client.write(
        f"{PLUGIN_MOUNT}/roles/{role_name}",
        keycloak_username=TEST_USER_STATIC,
        rotation_period="30m",
    )
    try:
        password_static1 = vault_client.read(
            f"{PLUGIN_MOUNT}/static-creds/{role_name}"
        )["data"]["password"]

        # Convert to ephemeral: static-creds stops serving, but the last
        # password remains valid in Keycloak.
        vault_client.write(
            f"{PLUGIN_MOUNT}/roles/{role_name}",
            ephemeral=True,
            ttl="1m",
            max_ttl="2m",
        )
        data = vault_client.read(f"{PLUGIN_MOUNT}/roles/{role_name}")["data"]
        assert data["ephemeral"] is True
        assert data["rotation_period"] == 0
        with pytest.raises(hvac.exceptions.InvalidRequest):
            vault_client.read(f"{PLUGIN_MOUNT}/static-creds/{role_name}")
        assert keycloak_auth_check(TEST_USER_STATIC, password_static1), (
            "the managed password must keep working after conversion to ephemeral"
        )

        # Convert back to static: an immediate rotation must produce a fresh
        # working credential (the pre-conversion one is replaced).
        vault_client.write(
            f"{PLUGIN_MOUNT}/roles/{role_name}",
            ephemeral=False,
            rotation_period="30m",
        )
        data = vault_client.read(f"{PLUGIN_MOUNT}/roles/{role_name}")["data"]
        assert data["ephemeral"] is False
        assert data["ttl"] == 0 and data["max_ttl"] == 0
        password_static2 = vault_client.read(
            f"{PLUGIN_MOUNT}/static-creds/{role_name}"
        )["data"]["password"]
        assert password_static2 != password_static1
        assert keycloak_auth_check(TEST_USER_STATIC, password_static2)
    finally:
        vault_client.delete(f"{PLUGIN_MOUNT}/roles/{role_name}")
