#!/bin/bash
set -e

# run unit tests and measure coverage
echo "running unit tests..."
go test -v -cover -covermode=count

# gofmt check
echo "checking formatting..."
test -z "$(gofmt -d -s . | tee /dev/stderr)"

# run linter
echo "running linter..."
if type "golangci-lint" &> /dev/null; then
    golangci-lint run --disable varcheck,deadcode,unused
else
    echo "WARNING: golangci-lint not installed. Only running go vet"
    echo "See: https://golangci-lint.run/usage/install/#local-installation"
    go vet ./...
fi
