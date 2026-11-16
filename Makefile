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
# make dev containers keep their own caches: Apple container will not share a
# volume between running containers, and make lint test must keep working
# while make dev runs.
# Renamed so no volume installed against the old in-repository pnpm store is reused.
DEV_NODE_MODULES_VOLUME := simple-siem-web-dev-modules
DEV_PNPM_STORE_VOLUME := simple-siem-web-dev-pnpm-store
DEV_GO_MOD_CACHE_VOLUME := simple-siem-dev-go-mod
DEV_GO_BUILD_CACHE_VOLUME := simple-siem-dev-go-build

POSTGRES_IMAGE := postgres:18-alpine
POSTGRES_CONTAINER := simple-siem-postgres
POSTGRES_VOLUME := simple-siem-postgres
# .env overrides the documented development defaults.
POSTGRES_ENV_FILE := $(if $(wildcard .env),.env,.env.example)
DEV_CONTAINER := simple-siem-api
WEB_CONTAINER := simple-siem-web
WEB_PORT ?= 5173

# Security stays on with HTTP basic auth so the seeder and fetcher exercise the
# same path as production; .env may override the development-only password.
ELASTICSEARCH_IMAGE ?= docker.elastic.co/elasticsearch/elasticsearch:9.1.0
ELASTICSEARCH_CONTAINER ?= simple-siem-elasticsearch
ELASTICSEARCH_VOLUME ?= simple-siem-elasticsearch
ELASTICSEARCH_PORT ?= 9200
ELASTICSEARCH_PASSWORD ?= simple_siem_dev
ELASTICSEARCH_8_IMAGE ?= docker.elastic.co/elasticsearch/elasticsearch:8.19.0
ELASTICSEARCH_8_CONTAINER ?= simple-siem-elasticsearch-8
ELASTICSEARCH_8_VOLUME ?= simple-siem-elasticsearch-8
ELASTICSEARCH_8_PORT ?= 9201

# Read the same values the containers receive, so RUN assembles one database
# URL from them instead of duplicating the defaults.
include $(POSTGRES_ENV_FILE)

# Apple container has no name resolution on user networks, so PostgreSQL and
# the API are published and reached through the gateway. Docker keeps using
# container names.
ifeq ($(CONTAINER),container)
POSTGRES_HOST ?= $(NETWORK_GATEWAY)
POSTGRES_PUBLISH ?= -p $(NETWORK_GATEWAY):5432:5432
# One host port cannot be published on two addresses, so Vite reaches the API
# through a second port on the gateway and the host keeps 127.0.0.1:8080.
API_HOST ?= $(NETWORK_GATEWAY)
API_PORT ?= 8081
API_PUBLISH ?= -p 127.0.0.1:8080:8080 -p $(NETWORK_GATEWAY):$(API_PORT):8080
ELASTICSEARCH_HOST ?= $(NETWORK_GATEWAY)
ELASTICSEARCH_PUBLISH ?= -p $(NETWORK_GATEWAY):$(ELASTICSEARCH_PORT):9200
ELASTICSEARCH_8_PUBLISH ?= -p $(NETWORK_GATEWAY):$(ELASTICSEARCH_8_PORT):9200
# The toolchain container reaches the published ports through the gateway.
ELASTICSEARCH_URL := http://$(ELASTICSEARCH_HOST):$(ELASTICSEARCH_PORT)
ELASTICSEARCH_8_URL := http://$(ELASTICSEARCH_HOST):$(ELASTICSEARCH_8_PORT)
else
POSTGRES_HOST ?= $(POSTGRES_CONTAINER)
POSTGRES_PUBLISH ?=
API_HOST ?= $(DEV_CONTAINER)
API_PORT ?= 8080
API_PUBLISH ?= -p 127.0.0.1:8080:8080
ELASTICSEARCH_HOST ?= $(ELASTICSEARCH_CONTAINER)
ELASTICSEARCH_PUBLISH ?= -p 127.0.0.1:$(ELASTICSEARCH_PORT):9200
ELASTICSEARCH_8_HOST ?= $(ELASTICSEARCH_8_CONTAINER)
ELASTICSEARCH_8_PUBLISH ?= -p 127.0.0.1:$(ELASTICSEARCH_8_PORT):9200
# Docker resolves container names on the network, so use the container port.
ELASTICSEARCH_URL := http://$(ELASTICSEARCH_HOST):9200
ELASTICSEARCH_8_URL := http://$(ELASTICSEARCH_8_HOST):9200
endif

DATABASE_URL := postgres://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@$(POSTGRES_HOST):5432/$(POSTGRES_DB)?sslmode=disable

E2E_DATABASE ?= simple_siem_e2e
E2E_DATABASE_URL := postgres://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@$(POSTGRES_HOST):5432/$(E2E_DATABASE)?sslmode=disable
# The e2e image extends the per-worktree toolchain image that .env overrides,
# so it is derived after the include above.
E2E_IMAGE := $(TOOLCHAIN_IMAGE)-e2e
E2E_STAMP := .make/e2e-$(CONTAINER).stamp
PLAYWRIGHT_VERSION := $(shell sed -n 's/.*"@playwright\/test": "\([^"]*\)".*/\1/p' web/package.json)

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
COMMON_RUN = $(CONTAINER) run --rm --memory $(TOOLCHAIN_MEMORY) --network $(NETWORK) --env-file $(POSTGRES_ENV_FILE) --env POSTGRES_HOST=$(POSTGRES_HOST) --env SIMPLE_SIEM_DATABASE_URL=$(DATABASE_URL) --env SIMPLE_SIEM_ENV=development --env ELASTICSEARCH_URL=$(ELASTICSEARCH_URL) --env ELASTICSEARCH_USERNAME=elastic --env ELASTICSEARCH_PASSWORD=$(ELASTICSEARCH_PASSWORD)
RUN = $(COMMON_RUN) -v $(CURDIR):/src -w /src -v $(GO_MOD_CACHE_VOLUME):/go/pkg/mod -v $(GO_BUILD_CACHE_VOLUME):/root/.cache/go-build

# Frontend commands run in web/ with the pnpm store and node_modules kept out
# of the Go build and the macOS bind mount. They do not mount the Go caches,
# because Apple container will not share a volume between running containers.
# The store and node_modules are separate volumes, so pnpm cannot hard-link;
# copy is set so that choice is deliberate, not a silent fallback.
PNPM_ENV = --env PNPM_CONFIG_STORE_DIR=/pnpm-store --env PNPM_CONFIG_PACKAGE_IMPORT_METHOD=copy
WEB_RUN = $(COMMON_RUN) -v $(CURDIR):/src -w /src/web -v $(PNPM_STORE_VOLUME):/pnpm-store -v $(NODE_MODULES_VOLUME):/src/web/node_modules $(PNPM_ENV)

.PHONY: toolchain network postgres test lint build e2e e2e-image run dev db-shell image debug down clean pnpm shadcn-mcp es es8 test-es test-es-run test-es8 seed-auth-logs

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

# Apple container does not initialize named-volume ownership, and the image
# runs as uid 1000, so give a new data volume to that user before first start.
# start_elasticsearch(name,volume,image,publish)
define start_elasticsearch
	@set -e; \
	if ! $(CONTAINER) start $(1) >/dev/null 2>&1; then \
		if ! $(CONTAINER) exec $(1) /bin/sh -c true >/dev/null 2>&1; then \
			$(CONTAINER) run --rm --user root --entrypoint /bin/sh -v $(2):/usr/share/elasticsearch/data $(3) -c 'chown -R 1000:0 /usr/share/elasticsearch/data'; \
			$(CONTAINER) run -d --name $(1) --network $(NETWORK) --memory 2g $(4) -v $(2):/usr/share/elasticsearch/data --env discovery.type=single-node --env xpack.security.enabled=true --env xpack.security.http.ssl.enabled=false --env xpack.security.transport.ssl.enabled=false --env node.store.allow_mmap=false --env ES_JAVA_OPTS="-Xms1g -Xmx1g" --env ELASTIC_PASSWORD=$(ELASTICSEARCH_PASSWORD) $(3); \
		fi; \
	fi
	@unauthorized=0; \
	for attempt in $$(seq 1 120); do \
		code=$$($(CONTAINER) exec $(1) curl -s -o /dev/null -w '%{http_code}' -u "elastic:$(ELASTICSEARCH_PASSWORD)" 'http://127.0.0.1:9200/_cluster/health?wait_for_status=yellow&timeout=1s' 2>/dev/null); \
		if [ "$$code" = "401" ]; then \
			unauthorized=1; \
		fi; \
		if [ "$$code" = "200" ]; then \
			exit 0; \
		fi; \
		if [ $$attempt -lt 120 ]; then sleep 1; fi; \
	done; \
	if [ "$$unauthorized" = "1" ]; then \
		echo "Elasticsearch rejected the password; the volume $(2) was created with a different ELASTICSEARCH_PASSWORD" >&2; \
	else \
		echo "Elasticsearch did not become healthy within 120 seconds" >&2; \
	fi; \
	exit 1
endef

es: network
	$(call start_elasticsearch,$(ELASTICSEARCH_CONTAINER),$(ELASTICSEARCH_VOLUME),$(ELASTICSEARCH_IMAGE),$(ELASTICSEARCH_PUBLISH))

es8: network
	$(call start_elasticsearch,$(ELASTICSEARCH_8_CONTAINER),$(ELASTICSEARCH_8_VOLUME),$(ELASTICSEARCH_8_IMAGE),$(ELASTICSEARCH_8_PUBLISH))

$(TOOLCHAIN_STAMP): Dockerfile
	@mkdir -p $(dir $@)
	$(CONTAINER) build --target toolchain -t $(TOOLCHAIN_IMAGE) .
	@touch $@

# The stamp alone misses an image deleted outside make, so check the image first.
e2e-image:
	@$(CONTAINER) image inspect $(E2E_IMAGE) >/dev/null 2>&1 || rm -f $(E2E_STAMP)
	@$(MAKE) --no-print-directory $(E2E_STAMP)

$(E2E_STAMP): Dockerfile web/package.json
	@mkdir -p $(dir $@)
	$(CONTAINER) build --target e2e --build-arg PLAYWRIGHT_VERSION=$(PLAYWRIGHT_VERSION) -t $(E2E_IMAGE) .
	@touch $@

test: postgres toolchain web/node_modules
	$(RUN) $(TOOLCHAIN_IMAGE) go test $(or $(GO_TEST_ARGS),./...)
	$(WEB_RUN) $(TOOLCHAIN_IMAGE) sh -c 'pnpm install --frozen-lockfile && pnpm test'

# The Elasticsearch integration suite is not part of plain `make test`: it
# fails, never skips, when the backend is missing.
test-es: es toolchain
	$(MAKE) --no-print-directory test-es-run

test-es-run:
	$(RUN) $(TOOLCHAIN_IMAGE) go test -count=1 -tags elasticsearch ./internal/fetcher/... ./internal/pipeline/... ./cmd/simple-siem/...

test-es8: es8 toolchain
	@set +e; \
	$(MAKE) --no-print-directory ELASTICSEARCH_URL=$(ELASTICSEARCH_8_URL) test-es-run; \
	status=$$?; \
	$(CONTAINER) stop $(ELASTICSEARCH_8_CONTAINER) >/dev/null 2>&1 || true; \
	exit $$status

lint: network toolchain web/node_modules
	$(RUN) $(TOOLCHAIN_IMAGE) golangci-lint run
	@if grep -rEln "from ['\"]cn['\"]" web/src; then echo "lint: the files above import the npm package cn; use @/lib/utils (see docs/frontend.md)" >&2; exit 1; fi; if grep -n '"cn":' web/package.json; then echo "lint: web/package.json declares the npm package cn; remove it" >&2; exit 1; fi
	$(WEB_RUN) $(TOOLCHAIN_IMAGE) sh -c 'pnpm install --frozen-lockfile && pnpm lint && pnpm typecheck'
# SHA pins stop a moved tag from changing what CI runs.
	$(RUN) $(TOOLCHAIN_IMAGE) sh -c 'govulncheck ./... && actionlint && { \
		quote=$$(printf "\047"); \
		extract="s/^([^:]+:[0-9]+).*[^[:alnum:]_]uses[$${quote}\"]?[[:space:]]*:[[:space:]]*[$${quote}\"]?([^[:space:],}$${quote}\"]*).*/\\1:\\2/p"; \
		allowed=":(\\./[^[:space:]]*|docker://[^[:space:]]+@sha256:[0-9a-f]{64}|[^@[:space:]]+@[0-9a-f]{40})$$"; \
		check_pins() { \
			sed -nE "$$extract" | grep -vE "$$allowed" | sed -E "s/^([^:]+:[0-9]+):.*/\\1/"; \
		}; \
		check_fixture() { \
			fixture=$$1; expected=$$2; \
			numbered=$$(printf "%s\n" "$$fixture" | awk "{print \"fixture:\" NR \":\" \$$0}"); \
			flagged=$$(printf "%s\n" "$$numbered" | check_pins); \
			flagged_count=$$(printf "%s\n" "$$flagged" | grep -c .); \
			total=$$(printf "%s\n" "$$fixture" | wc -l); \
			if { [ "$$expected" = unpinned ] && [ "$$flagged_count" -ne "$$total" ]; } || { [ "$$expected" = pinned ] && [ "$$flagged_count" -ne 0 ]; }; then \
				echo "pin check missed a fixture line" >&2; \
				printf "%s\n" "$$numbered" >&2; \
				printf "flagged:\n%s\n" "$$flagged" >&2; \
				exit 1; \
			fi; \
		}; \
		unpinned_fixture=$$(printf "%s\n" \
			"uses: actions/checkout@v4" \
			"- uses: actions/checkout@v4" \
			"- {uses: actions/checkout@v4}" \
			"- {name: x, uses: actions/checkout@v4}" \
			"\"uses\": actions/checkout@v4" \
			"$${quote}uses$${quote}: \"actions/checkout@v4\"" \
			"uses: docker://alpine:3"); \
		pinned_fixture=$$(printf "%s\n" \
			"uses: actions/checkout@1111111111111111111111111111111111111111" \
			"- {uses: \"actions/checkout@1111111111111111111111111111111111111111\"}" \
			"uses: ./.github/actions/setup" \
			"uses: docker://alpine@sha256:1111111111111111111111111111111111111111111111111111111111111111" \
			"uses: actions/checkout@1111111111111111111111111111111111111111 # v4" \
			"uses_count: 3"); \
		check_fixture "$$unpinned_fixture" unpinned; \
		check_fixture "$$pinned_fixture" pinned; \
		unpinned=$$(grep -rnH --include="*.yml" --include="*.yaml" "" .github | check_pins); \
		if [ -n "$$unpinned" ]; then \
			printf "%s\n" "$$unpinned" | sed "s/$$/: action not pinned to a full commit SHA/" >&2; \
			exit 1; \
		fi; \
	}'
	$(WEB_RUN) $(TOOLCHAIN_IMAGE) pnpm audit --prod

build: network toolchain web/node_modules
	$(WEB_RUN) $(TOOLCHAIN_IMAGE) sh -c 'pnpm install --frozen-lockfile && pnpm build'
	$(RUN) --env SIMPLE_SIEM_CHECK_WEB_BUILD=1 $(TOOLCHAIN_IMAGE) go test -count=1 -run TestBuiltFrontendIsSelfContained ./web
	$(RUN) $(TOOLCHAIN_IMAGE) sh -c 'mkdir -p bin && go build -trimpath -ldflags "$(LDFLAGS)" -o bin/simple-siem ./cmd/simple-siem'

e2e: postgres build e2e-image
	$(CONTAINER) exec $(POSTGRES_CONTAINER) sh -c 'psql -v ON_ERROR_STOP=1 -U "$$POSTGRES_USER" -d "$$POSTGRES_DB" -c "DROP DATABASE IF EXISTS $(E2E_DATABASE) WITH (FORCE)" -c "CREATE DATABASE $(E2E_DATABASE)"'
	$(WEB_RUN) --env SIMPLE_SIEM_DATABASE_URL=$(E2E_DATABASE_URL) --env SIMPLE_SIEM_LISTEN=127.0.0.1:8090 --env SIMPLE_SIEM_PUBLIC_URL=http://127.0.0.1:8090 $(E2E_IMAGE) sh -c 'pnpm install --frozen-lockfile && pnpm exec playwright test'

run: build
	$(RUN) $(TOOLCHAIN_IMAGE) ./bin/simple-siem $(ARGS)

seed-auth-logs: es toolchain
	$(RUN) $(TOOLCHAIN_IMAGE) go run ./cmd/seed-auth-logs $(ARGS)

web/node_modules:
	@mkdir -p $@

pnpm: network toolchain web/node_modules
	$(WEB_RUN) $(TOOLCHAIN_IMAGE) pnpm $(ARGS)

shadcn-mcp: network toolchain web/node_modules
	@$(WEB_RUN) -i $(TOOLCHAIN_IMAGE) pnpm --silent dlx shadcn@$(SHADCN_VERSION) mcp

dev: postgres toolchain web/node_modules
	@$(CONTAINER) rm -f $(WEB_CONTAINER) $(DEV_CONTAINER) >/dev/null 2>&1 || true
	$(COMMON_RUN) -d --name $(WEB_CONTAINER) -v $(CURDIR):/src -w /src/web -v $(DEV_NODE_MODULES_VOLUME):/src/web/node_modules -v $(DEV_PNPM_STORE_VOLUME):/pnpm-store $(PNPM_ENV) -p 127.0.0.1:$(WEB_PORT):$(WEB_PORT) --env API_HOST=$(API_HOST) --env API_PORT=$(API_PORT) --env WEB_PORT=$(WEB_PORT) $(TOOLCHAIN_IMAGE) sh -c 'pnpm install --frozen-lockfile && pnpm dev'
	$(COMMON_RUN) -v $(CURDIR):/src -w /src -v $(DEV_GO_MOD_CACHE_VOLUME):/go/pkg/mod -v $(DEV_GO_BUILD_CACHE_VOLUME):/root/.cache/go-build $(API_PUBLISH) --name $(DEV_CONTAINER) $(TOOLCHAIN_IMAGE) air -c .air.toml

db-shell: postgres
	$(CONTAINER) run --rm -i $(DB_SHELL_TTY) --network $(NETWORK) --env-file $(POSTGRES_ENV_FILE) $(POSTGRES_IMAGE) sh -c 'PGPASSWORD="$$POSTGRES_PASSWORD" exec psql -h $(POSTGRES_HOST) -U "$$POSTGRES_USER" -d "$$POSTGRES_DB"'

image: toolchain
	$(CONTAINER) build --target runtime --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t $(IMAGE) .

debug: postgres toolchain
	$(CONTAINER) build --target build --build-arg VERSION=$(VERSION) --build-arg COMMIT=$(COMMIT) -t $(DEBUG_IMAGE) .
	$(CONTAINER) run --rm -it --network $(NETWORK) --env-file $(POSTGRES_ENV_FILE) --env POSTGRES_HOST=$(POSTGRES_HOST) $(DEBUG_IMAGE) bash

down:
	@$(CONTAINER) stop $(POSTGRES_CONTAINER) $(DEV_CONTAINER) $(WEB_CONTAINER) $(ELASTICSEARCH_CONTAINER) 2>/dev/null || true

clean:
	@$(CONTAINER) rm -f $(POSTGRES_CONTAINER) $(DEV_CONTAINER) $(WEB_CONTAINER) $(ELASTICSEARCH_CONTAINER) 2>/dev/null || true
	@$(CONTAINER) network rm $(NETWORK) 2>/dev/null || true
	@$(CONTAINER) volume rm $(POSTGRES_VOLUME) $(ELASTICSEARCH_VOLUME) $(GO_MOD_CACHE_VOLUME) $(GO_BUILD_CACHE_VOLUME) $(PNPM_STORE_VOLUME) $(NODE_MODULES_VOLUME) $(DEV_NODE_MODULES_VOLUME) $(DEV_PNPM_STORE_VOLUME) $(DEV_GO_MOD_CACHE_VOLUME) $(DEV_GO_BUILD_CACHE_VOLUME) 2>/dev/null || true
	@$(CONTAINER) image rm $(TOOLCHAIN_IMAGE) 2>/dev/null || true
	rm -rf bin .make web/node_modules
