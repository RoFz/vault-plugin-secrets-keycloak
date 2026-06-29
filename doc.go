// Package secretsengine implements a HashiCorp Vault secrets engine plugin for
// Keycloak. It manages passwords for existing Keycloak realm users through the
// Keycloak Admin REST API; it never creates or deletes users.
//
// The backend (backend.go) is built on the Vault SDK's framework.Backend and
// registers the following paths:
//
//	config                  Keycloak connection and optional KV v2 sync settings.
//	roles/<name>            Map a Vault role to a Keycloak username (ephemeral or static).
//	creds/<name>            Ephemeral: a lease-bound password, fresh on every read.
//	static-creds/<name>     Static: the current autorotated password for the role.
//	users/                  List users in the target realm.
//	users/<name>            Read a user's details.
//	users/<name>/rotate     Rotate a user's password on demand.
//
// Static roles are autorotated in the background by a PeriodicFunc on each
// role's rotation_period; ephemeral roles issue lease-bound credentials that
// are invalidated on lease revoke. Every rotation can optionally be mirrored
// into a KV v2 secret.
//
// See docs/ARCHITECTURE.md for a fuller architectural overview.
package secretsengine
