#!/usr/bin/env bash
set -euo pipefail

export PATH="$HOME/go/bin:$HOME/.local/bin:$PATH"

echo "[devcontainer] Installing repo tooling..."

# Ensure Claude Code skips onboarding - ~/.claude.json is outside the bind-mounted
# ~/.claude dir, so it is not persisted automatically and must be seeded on each build.
test -f ~/.claude.json || echo '{"hasCompletedOnboarding":true,"installMethod":"native"}' > ~/.claude.json

# Go tools (pinned to match CI and pre-commit hooks)
echo "[devcontainer] Installing Go tools..."

go install mvdan.cc/gofumpt@v0.9.2
go install golang.org/x/vuln/cmd/govulncheck@v1.1.4
go install github.com/google/go-licenses@v1.6.0

# golangci-lint (pinned to match pre-commit-config.yaml and CI)
go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.11.4

# pre-commit (for local hook runs and gitlint)
pipx install pre-commit==4.6.0

# pip-tools (for regenerating tests/requirements.lock with --generate-hashes)
pipx install pip-tools==7.5.3

# CI-parity tooling: lint workflows/scripts and validate releases locally,
# matching the wrapper actions the CI workflows use.
echo "[devcontainer] Installing CI tools..."
mkdir -p "$HOME/.local/bin"

# actionlint — workflow linter (Lint-workflows CI job)
go install github.com/rhysd/actionlint/cmd/actionlint@v1.7.7

# static shellcheck binary — lints .github/scripts/*.sh (sha256-verified)
SHELLCHECK_VERSION=v0.10.0
SHELLCHECK_SHA256=6c881ab0698e4e6ea235245f22832860544f17ba386442fe7e9d629f8cbedf87
curl -fsSL "https://github.com/koalaman/shellcheck/releases/download/${SHELLCHECK_VERSION}/shellcheck-${SHELLCHECK_VERSION}.linux.x86_64.tar.xz" -o /tmp/shellcheck.tar.xz
echo "${SHELLCHECK_SHA256}  /tmp/shellcheck.tar.xz" | sha256sum -c -
tar -xJf /tmp/shellcheck.tar.xz -C /tmp
mv "/tmp/shellcheck-${SHELLCHECK_VERSION}/shellcheck" "$HOME/.local/bin/shellcheck"
rm -rf /tmp/shellcheck.tar.xz "/tmp/shellcheck-${SHELLCHECK_VERSION}"

# zizmor — GitHub Actions security linter (zizmor CI job)
pipx install zizmor==1.25.2

# cosign — release signature verification for `make release-validate` (sha256-verified)
COSIGN_VERSION=v3.0.6
COSIGN_SHA256=c956e5dfcac53d52bcf058360d579472f0c1d2d9b69f55209e256fe7783f4c74
curl -fsSL "https://github.com/sigstore/cosign/releases/download/${COSIGN_VERSION}/cosign-linux-amd64" -o /tmp/cosign
echo "${COSIGN_SHA256}  /tmp/cosign" | sha256sum -c -
mv /tmp/cosign "$HOME/.local/bin/cosign"
chmod +x "$HOME/.local/bin/cosign"

echo "[devcontainer] Tool versions:"
node --version
npm --version
go version
gofumpt --version || true
govulncheck -version 2>/dev/null || true
golangci-lint --version || true
pre-commit --version
pip-compile --version || true
actionlint --version || true
shellcheck --version || true
zizmor --version || true
cosign version 2>/dev/null || true
echo "[devcontainer] post-create complete."
