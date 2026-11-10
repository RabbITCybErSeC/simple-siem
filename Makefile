CONTAINER ?= container

TOOLCHAIN_IMAGE := simple-siem-toolchain
# Each container CLI has its own image store, so each needs its own stamp.
TOOLCHAIN_STAMP := .make/toolchain-$(CONTAINER).stamp
GO_MOD_CACHE_VOLUME := simple-siem-go-mod
GO_BUILD_CACHE_VOLUME := simple-siem-go-build
VERSION_PACKAGE := github.com/RabbITCybErSeC/simple-siem/internal/version
# $$(git ...) stays literal for the container shell, so the host needs no git.
LDFLAGS = -X $(VERSION_PACKAGE).Version=$$(git describe --tags --always --dirty) -X $(VERSION_PACKAGE).Commit=$$(git rev-parse --short HEAD)

ENV_FILE := $(wildcard .env)
RUN = $(CONTAINER) run --rm -v $(CURDIR):/src -w /src -v $(GO_MOD_CACHE_VOLUME):/go/pkg/mod -v $(GO_BUILD_CACHE_VOLUME):/root/.cache/go-build $(if $(ENV_FILE),--env-file $(ENV_FILE),)

.PHONY: toolchain test lint build run

toolchain: $(TOOLCHAIN_STAMP)

$(TOOLCHAIN_STAMP): Dockerfile
	@mkdir -p $(dir $@)
	$(CONTAINER) build --target toolchain -t $(TOOLCHAIN_IMAGE) .
	@touch $@

test: $(TOOLCHAIN_STAMP)
	$(RUN) $(TOOLCHAIN_IMAGE) go test ./...

lint: $(TOOLCHAIN_STAMP)
	$(RUN) $(TOOLCHAIN_IMAGE) golangci-lint run

build: $(TOOLCHAIN_STAMP)
	$(RUN) $(TOOLCHAIN_IMAGE) sh -c 'mkdir -p bin && go build -trimpath -ldflags "$(LDFLAGS)" -o bin/simple-siem ./cmd/simple-siem'

run: build
	$(RUN) $(TOOLCHAIN_IMAGE) ./bin/simple-siem $(ARGS)
