.PHONY: build build-test-binary test-unit test-integration test-integration-matrix lint check-deps pre-push all clean

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
	. ./tests/versions.env; \
	TESTCONTAINERS_RYUK_DISABLED=true \
	VAULT_VERSION="$${VAULT_VERSION:-$$VAULT_2X}" \
	KEYCLOAK_VERSION="$${KEYCLOAK_VERSION:-$$KEYCLOAK}" \
	pytest tests/integration/ -v --timeout=120

# Run all three Vault lines from tests/versions.env against the pinned Keycloak.
# Mirrors the CI integration matrix; one pytest session per line.
test-integration-matrix: build-test-binary
	. ./tests/versions.env; \
	for v in "$$VAULT_MPL" "$$VAULT_1X" "$$VAULT_2X"; do \
	  echo "==> Vault $$v x Keycloak $$KEYCLOAK"; \
	  TESTCONTAINERS_RYUK_DISABLED=true VAULT_VERSION="$$v" KEYCLOAK_VERSION="$$KEYCLOAK" \
	    pytest tests/integration/ -v --timeout=120 || exit 1; \
	done

# Fast checks — run after any Go source change.
lint:
	go vet ./...
	go run mvdan.cc/gofumpt@v0.9.2 -l .
	golangci-lint run ./...

# Slow checks — run only when go.mod or go.sum changes.
check-deps:
	go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...
	go run github.com/google/go-licenses@v1.6.0 report ./...

# Run all fast checks + unit tests before pushing.
# Run make test-integration separately when plugin behavior changes.
pre-push: lint test-unit check-deps

# Run everything including integration tests (requires Docker).
all: lint test-unit check-deps test-integration

clean:
	rm -rf $(BIN_DIR)/
