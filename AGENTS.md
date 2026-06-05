# Global Instructions

## Git Commits

- All commit messages must follow the Conventional Commits convention
- Subject line format: `<type>(<scope>): <description>`
- The body (after the subject) must start with a blank line, and list each change as a conventional commit identifier, one per line
- Example format:

  feat(auth): add OAuth2 login support

  feat(auth): add OAuth2 login handler
  feat(auth): integrate token refresh flow
  fix(auth): handle expired session edge case
  chore(deps): add oauth2 library

### Release-triggering commit types

Commit types drive versioning. Only use `fix:` or `feat:` when the change affects the **plugin's behavior as seen by users**:

- `feat:` triggers a minor release: use only when adding a new user-facing capability (new Vault path, new config field, new credential type, new API behavior)
- `fix:` triggers a patch release: use only when correcting incorrect plugin behavior (logic bug affecting users, or a CVE that is reachable through the plugin's own code paths, confirmed via govulncheck call traces)

Do NOT use `fix:` or `feat:` for:

- Dependency bumps where no plugin behavior changed (use `chore(deps):`)
- Security CVEs in transitive dependencies that are not reachable through plugin code paths (use `chore(deps):`)
- Test file changes (use `test:`)
- CI/workflow changes (use `ci:`)
- Formatting, linting, or staticcheck fixes (use `test:` for test files, `refactor:` for source files)

When in doubt about reachability of a CVE, run `govulncheck ./...` and check whether the finding shows real call traces or only `init()` chains. Init-only findings are not exploitable through the plugin.

## Local Checks Before Pushing

After making changes to Go source files, instruct the user to run:

- `make lint` — fast: vet, formatting, golangci-lint. Run after any Go source change.
- `make test-unit` — unit tests with race detector. Run after any Go source change.
- `make check-deps` — govulncheck + go-licenses. Run only when go.mod or go.sum changes.
- `make test-integration` — integration tests (requires Docker). Run when plugin behavior changes, before pushing.
- `make pre-push` — runs lint + test-unit + check-deps together. Shortcut before pushing non-integration changes.

Do not suggest running integration tests after every change. They require Docker and are slow.

## GitHub API

- When interacting with GitHub (e.g. checking workflow logs, reading or managing PRs, repository settings, releases), always favor the `gh` CLI over direct API calls or other methods
