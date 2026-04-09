.PHONY: build build-test-binary test-unit test-integration clean

BINARY_NAME := vault-plugin-secrets-keycloak
BIN_DIR     := bin

# Detect host architecture so the binary matches the Docker container runtime.
# Docker Desktop on Apple Silicon runs linux/arm64 containers; on Intel it runs
# linux/amd64. GOARCH maps uname -m output (x86_64 -> amd64, arm64 -> arm64).
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),arm64)
  GOARCH_TARGET := arm64
else
  GOARCH_TARGET := amd64
endif

build:
	go build ./...

# Compile for linux/<host-arch> — matches the OS/arch of the Vault container.
build-test-binary:
	@mkdir -p $(BIN_DIR)
	CGO_ENABLED=0 GOOS=linux GOARCH=$(GOARCH_TARGET) \
		go build -o $(BIN_DIR)/$(BINARY_NAME) \
		./cmd/$(BINARY_NAME)
	@chmod +x $(BIN_DIR)/$(BINARY_NAME)
	@echo "Built $(BIN_DIR)/$(BINARY_NAME) (linux/$(GOARCH_TARGET))"

test-unit:
	go test -race ./...

test-integration: build-test-binary
	pytest tests/integration/ -v --timeout=120

clean:
	rm -rf $(BIN_DIR)/
