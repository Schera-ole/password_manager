# Password Manager Makefile

# Project variables
PROJECT_NAME := password-manager
CLIENT_BIN := client
SERVER_BIN := server

# Version information
VERSION ?= dev
BUILD_DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build
GOCLEAN := $(GOCMD) clean
GOTEST := $(GOCMD) test
GOGET := $(GOCMD) get
GOMOD := $(GOCMD) mod

# Platform-specific variables
WINDOWS_CLIENT := $(CLIENT_BIN).exe
LINUX_CLIENT := $(CLIENT_BIN)
MACOS_CLIENT := $(CLIENT_BIN)-darwin

# ldflags for version and build date
LDFLAGS := -ldflags "-X 'github.com/Schera-ole/password_manager/cmd/client/cmd.buildVersion=$(VERSION)' \
                     -X 'github.com/Schera-ole/password_manager/cmd/client/cmd.buildDate=$(BUILD_DATE)' \
                     -X 'github.com/Schera-ole/password_manager/cmd/server/main.buildVersion=$(VERSION)' \
                     -X 'github.com/Schera-ole/password_manager/cmd/server/main.buildDate=$(BUILD_DATE)'"

.PHONY: all build clean test help

# Default target
all: build

# Build all binaries
build: build-client build-server

# Build client for current platform
build-client:
	$(GOBUILD) $(LDFLAGS) -o bin/$(CLIENT_BIN) ./cmd/client

# Build server for current platform
build-server:
	$(GOBUILD) $(LDFLAGS) -o bin/$(SERVER_BIN) ./cmd/server

# Cross-platform builds for client
build-client-windows:
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o bin/$(WINDOWS_CLIENT) ./cmd/client

build-client-linux:
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o bin/$(LINUX_CLIENT) ./cmd/client

build-client-macos:
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o bin/$(MACOS_CLIENT) ./cmd/client

# Cross-platform builds for server
build-server-windows:
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o bin/$(SERVER_BIN).exe ./cmd/server

build-server-linux:
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o bin/$(SERVER_BIN) ./cmd/server

build-server-macos:
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o bin/$(SERVER_BIN)-darwin ./cmd/server

# Cross-compilation targets for all platforms
cross-compile-client: build-client-windows build-client-linux build-client-macos

cross-compile-server: build-server-windows build-server-linux build-server-macos

cross-compile-all: cross-compile-client cross-compile-server

# Run tests
test:
	$(GOTEST) -v ./...

# Clean build artifacts
clean:
	$(GOCLEAN)
	rm -rf bin/

# Install dependencies
deps:
	$(GOMOD) tidy

# Display help
help:
	@echo "Available targets:"
	@echo "  all                    - Build both client and server for current platform (default)"
	@echo "  build                  - Build both client and server for current platform"
	@echo "  build-client           - Build client for current platform"
	@echo "  build-server           - Build server for current platform"
	@echo "  build-client-windows   - Build client for Windows"
	@echo "  build-client-linux     - Build client for Linux"
	@echo "  build-client-macos     - Build client for macOS"
	@echo "  build-server-windows   - Build server for Windows"
	@echo "  build-server-linux     - Build server for Linux"
	@echo "  build-server-macos     - Build server for macOS"
	@echo "  cross-compile-client   - Build client for all platforms"
	@echo "  cross-compile-server   - Build server for all platforms"
	@echo "  cross-compile-all      - Build both client and server for all platforms"
	@echo "  test                   - Run tests"
	@echo "  clean                  - Clean build artifacts"
	@echo "  deps                   - Install dependencies"
	@echo "  help                   - Display this help message"
	@echo ""
	@echo "Variables:"
	@echo "  VERSION                - Build version (default: dev)"
	@echo "  BUILD_DATE             - Build date (default: current UTC time)"