
.PHONY: build
build:
	go build -trimpath

.PHONY: deps
deps:
	go mod tidy
	go get -u
	go mod tidy

.PHONY: hostkey
hostkey:
	openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out hostkey.pem

.PHONY: me_sad
me_sad: test check

.PHONY: test
test:
	@echo "running unit tests..."
	go test -v -cover -covermode=count ./...
# go test -v -race -cover -covermode=atomic

.PHONY: check
check: gofmt lint

.PHONY: gofmt
gofmt:
# gofmt check
	@echo "checking formatting..."
	@test -z "$(gofmt -d -s . | tee /dev/stderr)"
	@echo "ok"

.PHONY: lint
lint:
	@echo "running linter..."
	@type "golangci-lint" > /dev/null 2>&1 || \
		( echo "ERROR: golangci-lint not installed. See: https://golangci-lint.run/usage/install/#local-installation" && false )
	@golangci-lint run -c .golangci.yaml --sort-results ./...
	@echo "ok"

.PHONY: vet
vet:
	go vet ./...
