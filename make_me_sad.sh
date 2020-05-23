#!/bin/bash
set -ev

# run unit tests and measure coverage
go test -v -cover -covermode=count

# gofmt check
test -z "$(gofmt -d -s . | tee /dev/stderr)"

# run go vet (kind of a linter)
go vet ./...
