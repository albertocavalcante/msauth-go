# msauth-go development commands

# Default recipe: run tests
default: test

# Build everything
build:
    go build ./...

# Run all tests
test:
    go tool -modfile=tools.go.mod gotestsum --format pkgname-and-test-fails -- ./...

# Run tests with the race detector
test-race:
    go tool -modfile=tools.go.mod gotestsum --format pkgname-and-test-fails -- -race ./...

# Run tests with verbose output
test-v:
    go tool -modfile=tools.go.mod gotestsum --format standard-verbose -- ./...

# Run tests with coverage
test-cover:
    go tool -modfile=tools.go.mod gotestsum --format pkgname-and-test-fails -- -coverprofile=coverage.out ./...
    go tool cover -html=coverage.out -o coverage.html

# Run golangci-lint
lint:
    go tool -modfile=tools.go.mod golangci-lint run --timeout=5m

# Format code
fmt:
    gofmt -w .

# Check formatting
fmt-check:
    test -z "$(gofmt -l .)"

# Run go vet
vet:
    go vet ./...

# Tidy go.mod
tidy:
    go mod tidy

# Tidy tools.go.mod
tidy-tools:
    go mod tidy -modfile=tools.go.mod

# Update goldens
update-goldens:
    MSAUTH_UPDATE_GOLDENS=1 go test ./...

# Full local CI emulation
ci: fmt-check vet test-race lint

# Clean build artifacts
clean:
    rm -rf bin/ coverage.out coverage.html
