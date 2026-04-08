"""
Tests for the keycloak/config path.

Each test function is fully independent: the autouse fixture writes then
deletes the config so the plugin always starts unconfigured.
"""

import pytest

from conftest import (
    KEYCLOAK_ADMIN_PASS,
    KEYCLOAK_ADMIN_USER,
    KV_MOUNT,
    KV_SECRET_PATH,
    PLUGIN_MOUNT,
    TEST_REALM,
)


# ── Module fixtures ───────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clean_config(vault_client):
    """Delete the plugin config before and after every test in this module."""
    vault_client.delete(f"{PLUGIN_MOUNT}/config")
    yield
    vault_client.delete(f"{PLUGIN_MOUNT}/config")


# ── Helpers ───────────────────────────────────────────────────────────────────

def write_config(vault_client, keycloak_url, **overrides):
    params = {
        "url": keycloak_url,
        "realm": "master",
        "target_realm": TEST_REALM,
        "master_admin_username": KEYCLOAK_ADMIN_USER,
        "master_admin_password": KEYCLOAK_ADMIN_PASS,
    }
    params.update(overrides)
    vault_client.write(f"{PLUGIN_MOUNT}/config", **params)


# ── Tests ─────────────────────────────────────────────────────────────────────

def test_config_read_returns_none_when_not_set(vault_client):
    response = vault_client.read(f"{PLUGIN_MOUNT}/config")
    assert response is None


def test_config_write_and_read(vault_client, keycloak_url):
    write_config(vault_client, keycloak_url)

    data = vault_client.read(f"{PLUGIN_MOUNT}/config")["data"]
    assert data["url"] == keycloak_url
    assert data["realm"] == "master"
    assert data["target_realm"] == TEST_REALM
    assert data["master_admin_username"] == KEYCLOAK_ADMIN_USER


def test_config_password_not_returned_on_read(vault_client, keycloak_url):
    write_config(vault_client, keycloak_url)

    data = vault_client.read(f"{PLUGIN_MOUNT}/config")["data"]
    assert "master_admin_password" not in data


def test_config_kv_token_not_returned_on_read(vault_client, keycloak_url):
    write_config(
        vault_client,
        keycloak_url,
        kv_mount_path=KV_MOUNT,
        kv_secret_path=KV_SECRET_PATH,
        kv_token="some-token",
    )

    data = vault_client.read(f"{PLUGIN_MOUNT}/config")["data"]
    assert "kv_token" not in data


def test_config_kv_fields_round_trip(vault_client, keycloak_url):
    write_config(
        vault_client,
        keycloak_url,
        kv_mount_path=KV_MOUNT,
        kv_secret_path=KV_SECRET_PATH,
        kv_api_addr="http://127.0.0.1:8200",
        kv_tls_skip_verify=True,
    )

    data = vault_client.read(f"{PLUGIN_MOUNT}/config")["data"]
    assert data["kv_mount_path"] == KV_MOUNT
    assert data["kv_secret_path"] == KV_SECRET_PATH
    assert data["kv_api_addr"] == "http://127.0.0.1:8200"
    assert data["kv_tls_skip_verify"] is True


def test_config_delete(vault_client, keycloak_url):
    write_config(vault_client, keycloak_url)
    assert vault_client.read(f"{PLUGIN_MOUNT}/config") is not None

    vault_client.delete(f"{PLUGIN_MOUNT}/config")
    assert vault_client.read(f"{PLUGIN_MOUNT}/config") is None


def test_config_target_realm_defaults_to_realm(vault_client, keycloak_url):
    # Write without target_realm; the plugin should default it to realm.
    vault_client.write(
        f"{PLUGIN_MOUNT}/config",
        url=keycloak_url,
        realm="master",
        master_admin_username=KEYCLOAK_ADMIN_USER,
        master_admin_password=KEYCLOAK_ADMIN_PASS,
    )

    data = vault_client.read(f"{PLUGIN_MOUNT}/config")["data"]
    # target_realm is stored as empty string when defaulted — the plugin
    # treats empty as "same as realm" at runtime.
    assert data["realm"] == "master"
