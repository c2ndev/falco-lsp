# Falco LSP - Makefile
# Build system for Falco Language Server

BINARY_NAME := falco-lang
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")

# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOVET := $(GOCMD) vet
GOFMT := gofmt
GOMOD := $(GOCMD) mod

# Build flags
LDFLAGS := -ldflags "-s -w \
	-X github.com/falcosecurity/falco-lsp/internal/version.Version=$(VERSION) \
	-X github.com/falcosecurity/falco-lsp/internal/version.Commit=$(COMMIT) \
	-X github.com/falcosecurity/falco-lsp/internal/version.BuildTime=$(BUILD_TIME)"

# Directories
BUILD_DIR := build
CMD_DIR := ./cmd/falco-lang

# Output binary
OUTPUT := $(BUILD_DIR)/$(BINARY_NAME)

.PHONY: all build build-all build-extension clean test test-cover lint fmt vet deps help install

# Default target
all: lint test build

## Build

build: ## Build the binary for current platform
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(LDFLAGS) -o $(OUTPUT) $(CMD_DIR)
	@echo "Built $(OUTPUT)"

build-all: ## Build for all platforms
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD_DIR)
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(CMD_DIR)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(CMD_DIR)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(CMD_DIR)
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(CMD_DIR)
	@echo "Built binaries for all platforms in $(BUILD_DIR)/"

build-extension: build-all ## Build binaries and copy to VS Code extension
	@echo "Copying binaries to vscode-extension/bin/..."
	@mkdir -p ../vscode-extension/bin
	cp $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 ../vscode-extension/bin/
	cp $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 ../vscode-extension/bin/
	cp $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 ../vscode-extension/bin/
	cp $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 ../vscode-extension/bin/
	cp $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe ../vscode-extension/bin/
	@echo "✅ Binaries copied to vscode-extension/bin/"

install: build ## Install the binary to $GOPATH/bin
	cp $(OUTPUT) $(GOPATH)/bin/$(BINARY_NAME)
	@echo "Installed $(BINARY_NAME) to $(GOPATH)/bin/"

## Development

deps: ## Download dependencies
	$(GOMOD) download
	$(GOMOD) tidy

fmt: ## Format code
	$(GOFMT) -s -w .

vet: ## Run go vet
	$(GOVET) ./...

lint: ## Run golangci-lint
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci-lint/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run ./...

## Testing

test: ## Run tests
	$(GOTEST) -v -race ./...

test-cover: ## Run tests with coverage
	@mkdir -p $(BUILD_DIR)
	$(GOTEST) -v -race -coverprofile=$(BUILD_DIR)/coverage.out ./...
	$(GOCMD) tool cover -html=$(BUILD_DIR)/coverage.out -o $(BUILD_DIR)/coverage.html
	@echo "Coverage report: $(BUILD_DIR)/coverage.html"

test-integration: ## Run integration tests
	$(GOTEST) -v -race -tags=integration ./...

bench: ## Run benchmarks
	$(GOTEST) -bench=. -benchmem ./...

## Maintenance

clean: ## Remove build artifacts
	rm -rf $(BUILD_DIR)
	$(GOCMD) clean

update-deps: ## Update all dependencies
	$(GOMOD) get -u ./...
	$(GOMOD) tidy

## Help

help: ## Show this help
	@echo "Falco LSP - Available targets:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
