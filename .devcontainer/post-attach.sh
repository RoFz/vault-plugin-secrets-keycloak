#!/usr/bin/env bash
# Runs each time VS Code attaches to the container (after extensions are installed).

# Install Go tools for the gopls language server if not already present.
# The golang.go extension manages gopls, dlv, and staticcheck via its own
# toolchain — no manual intervention needed here.
echo "[post-attach] Ready."
