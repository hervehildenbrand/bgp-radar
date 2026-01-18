.PHONY: build run test clean docker docker-run lint vet fmt help

# Binary name
BINARY := bgp-radar

# Build info
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)"

# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOCLEAN := $(GOCMD) clean
GOVET := $(GOCMD) vet
GOFMT := gofmt

# Default target
all: build

## build: Build the binary
build:
	$(GOBUILD) $(LDFLAGS) -o $(BINARY) ./cmd/bgp-radar

## build-linux: Build for Linux (amd64)
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY)-linux-amd64 ./cmd/bgp-radar

## build-darwin: Build for macOS (arm64)
build-darwin:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BINARY)-darwin-arm64 ./cmd/bgp-radar

## run: Run with default settings
run: build
	./$(BINARY) -collectors=rrc00

## test: Run tests
test:
	$(GOTEST) -v -race ./...

## test-coverage: Run tests with coverage
test-coverage:
	$(GOTEST) -v -race -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

## lint: Run linter (requires golangci-lint)
lint:
	golangci-lint run ./...

## vet: Run go vet
vet:
	$(GOVET) ./...

## fmt: Format code
fmt:
	$(GOFMT) -s -w .

## clean: Clean build artifacts
clean:
	$(GOCLEAN)
	rm -f $(BINARY) $(BINARY)-linux-amd64 $(BINARY)-darwin-arm64
	rm -f coverage.out coverage.html

## docker: Build Docker image
docker:
	docker build -t $(BINARY):latest .

## docker-run: Run Docker container
docker-run: docker
	docker run --rm -it $(BINARY):latest -collectors=rrc00

## docker-compose: Run with docker-compose
docker-compose:
	docker-compose -f examples/docker-compose.yml up -d

## docker-compose-down: Stop docker-compose
docker-compose-down:
	docker-compose -f examples/docker-compose.yml down

## deps: Download dependencies
deps:
	$(GOCMD) mod download
	$(GOCMD) mod tidy

## help: Show this help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^##//p' $(MAKEFILE_LIST) | column -t -s ':' | sed -e 's/^/ /'
