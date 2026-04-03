# Contributing

By participating in this project, you agree to abide by the
[Code of Conduct](CODE_OF_CONDUCT.md).

## Reporting Security Vulnerabilities

Please **do not** open a public issue for security vulnerabilities.
See [SECURITY.md](SECURITY.md) for the responsible disclosure process.

## Prerequisites

- [Go](https://go.dev/doc/install) — version specified in [`go.mod`](go.mod)
- A running [HashiCorp Vault](https://developer.hashicorp.com/vault/docs/install)
  and [Keycloak](https://www.keycloak.org/getting-started) instance for
  integration testing

## Getting Started

```sh
git clone https://github.com/RoFz/vault-plugin-secrets-keycloak.git
cd vault-plugin-secrets-keycloak
go mod tidy
go build ./...
```

## Running Tests

```sh
go test ./...
```

## Linting

The CI pipeline enforces linting via
[golangci-lint](https://golangci-lint.run/). To run it locally:

```sh
golangci-lint run
```

Code must also be formatted with [gofumpt](https://github.com/mvdan/gofumpt):

```sh
gofumpt -w .
```

## Commit Messages

This project uses [Conventional Commits](https://www.conventionalcommits.org/).
Commit messages drive automated versioning via release-please:

| Prefix | Effect |
| --- | --- |
| `feat:` | New feature → minor version bump |
| `feat!:` or `fix!:` | Breaking change → major version bump |
| `fix:` | Bug fix → patch version bump |
| `docs:` | Documentation only — no release |
| `ci:` | CI/CD changes — no release |
| `chore:` | Maintenance — no release |
| `test:` | Test changes — no release |

A breaking change can also be indicated by adding `BREAKING CHANGE:` in the
commit body footer.

## Submitting a Pull Request

1. For non-trivial changes, open an issue first to discuss the approach.
2. Fork the repository and create a branch from `main`.
3. Make your changes, including tests for new behaviour.
4. Ensure `go test ./...` and `golangci-lint run` pass locally.
5. Write commit messages following the Conventional Commits format above.
6. Open a pull request against `main`. Keep each PR to a single logical change.

## References

- [GitHub Docs — Setting guidelines for repository contributors](https://docs.github.com/en/communities/setting-up-your-project-for-healthy-contributions/setting-guidelines-for-repository-contributors)
- [goreleaser/goreleaser — CONTRIBUTING.md](https://github.com/goreleaser/goreleaser/blob/main/CONTRIBUTING.md) (pattern reference)
- [Conventional Commits specification](https://www.conventionalcommits.org/en/v1.0.0/)
- [opensource.guide — How to Contribute to Open Source](https://opensource.guide/how-to-contribute/)
