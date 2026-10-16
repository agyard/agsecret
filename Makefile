SHELL := /bin/sh
GO ?= go
VERSION ?= dev
GOMEMLIMIT ?= 512MiB
TEST_TIMEOUT ?= 2m
LDFLAGS := -s -w -X github.com/thezzisu/agsecret/internal/cli.Version=$(VERSION)

.PHONY: build test check integration clean

build:
	mkdir -p bin
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/agsecret ./cmd/agsecret

test:
	GOMEMLIMIT=$(GOMEMLIMIT) CGO_ENABLED=0 sh scripts/bounded-check.sh $(GO) test -p 1 -timeout $(TEST_TIMEOUT) ./...

check:
	CGO_ENABLED=0 sh scripts/bounded-check.sh $(GO) vet -p 1 ./...

integration:
	sh scripts/bounded-check.sh $(MAKE) build
	sh scripts/bounded-check.sh python3 tests/e2e.py

clean:
	rm -rf bin
