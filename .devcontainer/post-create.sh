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
pipx install pre-commit

# pip-tools (for regenerating tests/requirements.lock with --generate-hashes)
pipx install pip-tools

echo "[devcontainer] Tool versions:"
node --version
npm --version
go version
gofumpt --version || true
govulncheck -version 2>/dev/null || true
golangci-lint --version || true
pre-commit --version
pip-compile --version || true
echo "[devcontainer] post-create complete."
