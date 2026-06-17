default: fmt lint install generate

build:
	go build -v ./...

install: build
	go install -v ./...

lint:
	golangci-lint run

generate:
	cd tools; go generate ./...

fmt:
	gofmt -s -w -e .

test:
	go test -v -cover -count=1 -timeout=120s ./...

testacc:
	TF_ACC=1 go test -v -cover -count=1 -timeout 120m -p=1 ./...

# testacc-run targets a subset of acceptance tests. Override RUN (Go -run regex)
# and PKG (package path) on the command line. Defaults match `make testacc`
# scope but accept TESTARGS for extra flags.
#
# Examples:
#   make testacc-run RUN=TestAccDataForwardingResource_writeOnlySecret \
#     PKG=./internal/resources/data_forwarding/...
#   make testacc-run TESTARGS='-failfast'
RUN ?= .
PKG ?= ./...
TESTARGS ?=
testacc-run:
	TF_ACC=1 go test -v -cover -count=1 -timeout 120m -p=1 -run '$(RUN)' $(TESTARGS) $(PKG)

.PHONY: fmt lint test testacc testacc-run build install generate