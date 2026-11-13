CONTAINER ?= container
NETWORK := simple-siem
NETWORK_SUBNET := 192.168.100.0/24
NETWORK_GATEWAY := 192.168.100.1

TOOLCHAIN_IMAGE := simple-siem-toolchain
# Each container CLI has its own image store, so each needs its own stamp.
TOOLCHAIN_STAMP := .make/toolchain-$(CONTAINER).stamp
GO_MOD_CACHE_VOLUME := simple-siem-go-mod
GO_BUILD_CACHE_VOLUME := simple-siem-go-build
PNPM_STORE_VOLUME := simple-siem-pnpm-store
NODE_MODULES_VOLUME := simple-siem-web-node-modules

POSTGRES_IMAGE := postgres:18-alpine
POSTGRES_CONTAINER := simple-siem-postgres
POSTGRES_VOLUME := simple-siem-postgres
# .env overrides the documented development defaults.
POSTGRES_ENV_FILE := $(if $(wildcard .env),.env,.env.example)
DEV_CONTAINER := simple-siem-api
WEB_CONTAINER := simple-siem-web
WEB_PORT ?= 5173

# Read the same values the containers receive, so RUN assembles one database
# URL from them instead of duplicating the defaults.
include $(POSTGRES_ENV_FILE)

# Apple container has no name resolution on user networks, so PostgreSQL and
# the API are published and reached through the gateway. Docker keeps using
# container names.
ifeq ($(CONTAINER),container)
POSTGRES_HOST ?= $(NETWORK_GATEWAY)
POSTGRES_PUBLISH ?= -p $(NETWORK_GATEWAY):5432:5432
API_HOST ?= $(NETWORK_GATEWAY)
API_PUBLISH ?= -p $(NETWORK_GATEWAY):8080:8080
else
POSTGRES_HOST ?= $(POSTGRES_CONTAINER)
POSTGRES_PUBLISH ?=
API_HOST ?= $(DEV_CONTAINER)
API_PUBLISH ?= -p 127.0.0.1:8080:8080
endif

DATABASE_URL := postgres://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@$(POSTGRES_HOST):5432/$(POSTGRES_DB)?sslmode=disable

VERSION_PACKAGE := github.com/RabbITCybErSeC/simple-siem/internal/version
# Apple Git ships with the Xcode command line tools that also provide make.
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS := -X $(VERSION_PACKAGE).Version=$(VERSION) -X $(VERSION_PACKAGE).Commit=$(COMMIT)
IMAGE := simple-siem:dev
DEBUG_IMAGE := simple-siem-build:dev
SHADCN_VERSION := 4.23.0

# A TTY only for interactive psql; piped queries must not allocate one.
DB_SHELL_TTY := $(shell test -t 0 && echo -t)
# Apple container gives a container 1 GiB by default; cold Go builds of the
# dependencies need more.
TOOLCHAIN_MEMORY := 4g
COMMON_RUN = $(CONTAINER) run --rm --memory $(TOOLCHAIN_MEMORY) --network $(NETWORK) --env-file $(POSTGRES_ENV_FILE) --env POSTGRES_HOST=$(POSTGRES_HOST) --env SIMPLE_SIEM_DATABASE_URL=$(DATABASE_URL) --env SIMPLE_SIEM_ENV=development
RUN = $(COMMON_RUN) -v $(CURDIR):/src -w /src -v $(GO_MOD_CACHE_VOLUME):/go/pkg/mod -v $(GO_BUILD_CACHE_VOLUME):/root/.cache/go-build

# Frontend commands run in web/ with the pnpm store and node_modules kept out
# of the Go build and the macOS bind mount. They do not mount the Go caches,
# because Apple container will not share a volume between running containers.
WEB_RUN = $(COMMON_RUN) -v $(CURDIR):/src -w /src/web -v $(PNPM_STORE_VOLUME):/pnpm-store -v $(NODE_MODULES_VOLUME):/src/web/node_modules --env PNPM_CONFIG_STORE_DIR=/pnpm-store

.PHONY: toolchain network postgres test lint build run dev db-shell image debug down clean pnpm shadcn-mcp

# The stamp alone misses an image deleted outside make, so check the image first.
toolchain:
	@$(CONTAINER) image inspect $(TOOLCHAIN_IMAGE) >/dev/null 2>&1 || rm -f $(TOOLCHAIN_STAMP)
	@$(MAKE) --no-print-directory $(TOOLCHAIN_STAMP)

# Apple container prints [] instead of failing when the network is missing.
network:
	@test "$$($(CONTAINER) network inspect $(NETWORK) 2>/dev/null)" != "[]" || $(CONTAINER) network create --subnet $(NETWORK_SUBNET) $(NETWORK)

postgres: network
	@$(CONTAINER) start $(POSTGRES_CONTAINER) >/dev/null 2>&1 || $(CONTAINER) run -d --name $(POSTGRES_CONTAINER) --network $(NETWORK) $(POSTGRES_PUBLISH) --env-file $(POSTGRES_ENV_FILE) -v $(POSTGRES_VOLUME):/var/lib/postgresql $(POSTGRES_IMAGE)
	@for attempt in $$(seq 1 30); do \
		if $(CONTAINER) exec $(POSTGRES_CONTAINER) pg_isready -h 127.0.0.1 -U "$(POSTGRES_USER)" -d "$(POSTGRES_DB)" >/dev/null 2>&1; then \
			exit 0; \
		fi; \
		if [ $$attempt -lt 30 ]; then sleep 1; fi; \
	done; \
	echo "PostgreSQL did not accept connections within 30 seconds" >&2; \
	exit 1

$(TOOLCHAIN_STAMP): Dockerfile
	@mkdir -p $(dir $@)
	$(CONTAINER) build --target toolchain -t $(TOOLCHAIN_IMAGE) .
	@touch $@

test: postgres toolchain web/node_modules
	$(RUN) $(TOOLCHAIN_IMAGE) go test ./...
	$(WEB_RUN) $(TOOLCHAIN_IMAGE) sh -c 'pnpm install --frozen-lockfile && pnpm test'

lint: network toolchain web/node_modules
	$(RUN) $(TOOLCHAIN_IMAGE) golangci-lint run
	$(WEB_RUN) $(TOOLCHAIN_IMAGE) sh -c 'pnpm install --frozen-lockfile && pnpm lint && pnpm typecheck'

build: network toolchain web/node_modules
	$(WEB_RUN) $(TOOLCHAIN_IMAGE) sh -c 'pnpm install --frozen-lockfile && pnpm build'
	$(RUN) $(TOOLCHAIN_IMAGE) sh -c 'mkdir -p bin && go build -trimpath -ldflags "$(LDFLAGS)" -o bin/simple-siem ./cmd/simple-siem'

run: build
	$(RUN) $(TOOLCHAIN_IMAGE) ./bin/simple-siem $(ARGS)

web/node_modules:
	@mkdir -p $@

pnpm: network toolchain web/node_modules
	$(WEB_RUN) $(TOOLCHAIN_IMAGE) pnpm $(ARGS)

shadcn-mcp: network toolchain web/node_modules
	@$(WEB_RUN) -i $(TOOLCHAIN_IMAGE) pnpm --silent dlx shadcn@$(SHADCN_VERSION) mcp

dev: postgres toolchain web/node_modules
	@$(CONTAINER) rm -f $(WEB_CONTAINER) $(DEV_CONTAINER) >/dev/null 2>&1 || true
	$(WEB_RUN) -d --name $(WEB_CONTAINER) -p 127.0.0.1:$(WEB_PORT):$(WEB_PORT) --env API_HOST=$(API_HOST) --env WEB_PORT=$(WEB_PORT) $(TOOLCHAIN_IMAGE) sh -c 'pnpm install --frozen-lockfile && pnpm dev'
	$(RUN) $(API_PUBLISH) --name $(DEV_CONTAINER) $(TOOLCHAIN_IMAGE) air -c .air.toml

db-shell: postgres
	$(CONTAINER) run --rm -i $(DB_SHELL_TTY) --network $(NETWORK) --env-file $(POSTGRES_ENV_FILE) $(POSTGRES_IMAGE) sh -c 'PGPASSWORD="$$POSTGRES_PASSWORD" exec psql -h $(POSTGRES_HOST) -U "$$POSTGRES_USER" -d "$$POSTGRES_DB"'

image: toolchain
	$(CONTAINER) build --target runtime --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t $(IMAGE) .

debug: postgres toolchain
	$(CONTAINER) build --target build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t $(DEBUG_IMAGE) .
	$(CONTAINER) run --rm -it --network $(NETWORK) --env-file $(POSTGRES_ENV_FILE) --env POSTGRES_HOST=$(POSTGRES_HOST) $(DEBUG_IMAGE) bash

down:
	@$(CONTAINER) stop $(POSTGRES_CONTAINER) $(DEV_CONTAINER) $(WEB_CONTAINER) 2>/dev/null || true

clean:
	@$(CONTAINER) rm -f $(POSTGRES_CONTAINER) $(DEV_CONTAINER) $(WEB_CONTAINER) 2>/dev/null || true
	@$(CONTAINER) network rm $(NETWORK) 2>/dev/null || true
	@$(CONTAINER) volume rm $(POSTGRES_VOLUME) $(GO_MOD_CACHE_VOLUME) $(GO_BUILD_CACHE_VOLUME) $(PNPM_STORE_VOLUME) $(NODE_MODULES_VOLUME) 2>/dev/null || true
	@$(CONTAINER) image rm $(TOOLCHAIN_IMAGE) 2>/dev/null || true
	rm -rf bin .make web/node_modules
