GO ?= go

.PHONY: test build

test:
	$(GO) test ./...

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags="-s -w" -o bin/kubelego ./cmd/kubelego
