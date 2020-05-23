#!/bin/bash
set -ev

# run unit tests and measure coverage
go test -v -cover -covermode=count

# gofmt check
test -z "$(gofmt -d -s . | tee /dev/stderr)"

# run linter
if type "golangci-lint" > /dev/null; then
    golangci-lint run --disable varcheck,deadcode,unused
else
    echo "WARNING: golangci-lint not installed. Only running go vet"
    echo "See: https://golangci-lint.run/usage/install/#local-installation"
    go vet ./...
fi
