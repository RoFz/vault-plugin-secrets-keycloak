FROM mcr.microsoft.com/devcontainers/base@sha256:bb779775cfc7d2e65f9b0f80f17770878f5a50c00d15cc873b627c5c214ce37e

RUN apt-get update \
    && apt-get install -y --no-install-recommends pipx python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /home/vscode/.claude /home/vscode/.vscode-server \
    && chown vscode:vscode /home/vscode/.claude /home/vscode/.vscode-server \
    && chmod 777 /home/vscode/.vscode-server
