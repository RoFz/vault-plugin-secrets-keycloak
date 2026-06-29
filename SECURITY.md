# Security Policy

## Supported Versions

Only the latest release is supported with security fixes.

## Reporting a Vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report vulnerabilities privately using
[GitHub Security Advisories](https://github.com/RoFz/vault-plugin-secrets-keycloak/security/advisories/new).
You will receive an acknowledgement within 7 days.

## Scope

In scope:

- Vulnerabilities in this plugin's code that could compromise the
  confidentiality, integrity, or availability of Vault or Keycloak credentials
- Dependency vulnerabilities with a direct exploit path

Out of scope:

- Vulnerabilities in HashiCorp Vault itself — report those to
  [HashiCorp](https://www.hashicorp.com/security)
- Vulnerabilities in Keycloak itself — report those to the
  [Keycloak project](https://www.keycloak.org/security)
- Issues requiring physical access or social engineering

## Disclosure

Once a fix is released, vulnerabilities will be publicly disclosed via a
GitHub Security Advisory. Credit will be given to the reporter unless
anonymity is requested.

## References

This policy was shaped by the following sources:

- [GitHub Docs — Adding a security policy to your repository](https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository)
- [GitHub Docs — Using private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing/privately-reporting-a-security-vulnerability)
- [goreleaser/goreleaser — SECURITY.md](https://github.com/goreleaser/goreleaser/blob/main/SECURITY.md) (pattern reference)
- [HashiCorp security disclosure policy](https://www.hashicorp.com/security)

## Security reviews

Internal security reviews of major features are documented in the repository:

- [Static roles and autorotation (v0.3.0)](docs/security-review-v0.3.0.md):
  full-source review of the autorotation feature (all findings resolved
  before release), plus a 2026-06-14 rotation-atomicity follow-up whose open
  findings are tracked as issues.

## Production hardening

[Production hardening posture](docs/production-hardening.md) maps the plugin
against HashiCorp's Vault production-hardening recommendations, marking each
baseline and extended item as either met by the plugin or this repository, or
an operator deployment / Vault-configuration responsibility.
