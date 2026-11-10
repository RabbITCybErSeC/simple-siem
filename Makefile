CONTAINER ?= container
NETWORK := simple-siem
NETWORK_SUBNET := 192.168.100.0/24
NETWORK_GATEWAY := 192.168.100.1

TOOLCHAIN_IMAGE := simple-siem-toolchain
# Each container CLI has its own image store, so each needs its own stamp.
TOOLCHAIN_STAMP := .make/toolchain-$(CONTAINER).stamp
GO_MOD_CACHE_VOLUME := simple-siem-go-mod
GO_BUILD_CACHE_VOLUME := simple-siem-go-build

POSTGRES_IMAGE := postgres:18-alpine
POSTGRES_CONTAINER := simple-siem-postgres
POSTGRES_VOLUME := simple-siem-postgres
# .env overrides the documented development defaults.
POSTGRES_ENV_FILE := $(if $(wildcard .env),.env,.env.example)
DEV_CONTAINER := simple-siem-api

# Apple container has no name resolution on user networks, so PostgreSQL is
# published and reached through the gateway. Docker keeps using its name.
ifeq ($(CONTAINER),container)
POSTGRES_HOST ?= $(NETWORK_GATEWAY)
POSTGRES_PUBLISH ?= -p $(NETWORK_GATEWAY):5432:5432
else
POSTGRES_HOST ?= $(POSTGRES_CONTAINER)
POSTGRES_PUBLISH ?=
endif

VERSION_PACKAGE := github.com/RabbITCybErSeC/simple-siem/internal/version
# $$(git ...) stays literal for the container shell, so the host needs no git.
LDFLAGS = -X $(VERSION_PACKAGE).Version=$$(git describe --tags --always --dirty) -X $(VERSION_PACKAGE).Commit=$$(git rev-parse --short HEAD)

ENV_FILE := $(wildcard .env)
RUN = $(CONTAINER) run --rm --network $(NETWORK) -v $(CURDIR):/src -w /src -v $(GO_MOD_CACHE_VOLUME):/go/pkg/mod -v $(GO_BUILD_CACHE_VOLUME):/root/.cache/go-build $(if $(ENV_FILE),--env-file $(ENV_FILE),)

.PHONY: toolchain network postgres test lint build run dev db-shell down clean

toolchain: $(TOOLCHAIN_STAMP)

network:
	@$(CONTAINER) network list | grep -qw '$(NETWORK)' || $(CONTAINER) network create --subnet $(NETWORK_SUBNET) $(NETWORK)

postgres: network
	@$(CONTAINER) start $(POSTGRES_CONTAINER) >/dev/null 2>&1 || $(CONTAINER) run -d --name $(POSTGRES_CONTAINER) --network $(NETWORK) $(POSTGRES_PUBLISH) --env-file $(POSTGRES_ENV_FILE) -v $(POSTGRES_VOLUME):/var/lib/postgresql $(POSTGRES_IMAGE)

$(TOOLCHAIN_STAMP): Dockerfile
	@mkdir -p $(dir $@)
	$(CONTAINER) build --target toolchain -t $(TOOLCHAIN_IMAGE) .
	@touch $@

test: postgres $(TOOLCHAIN_STAMP)
	$(RUN) $(TOOLCHAIN_IMAGE) go test ./...

lint: network $(TOOLCHAIN_STAMP)
	$(RUN) $(TOOLCHAIN_IMAGE) golangci-lint run

build: network $(TOOLCHAIN_STAMP)
	$(RUN) $(TOOLCHAIN_IMAGE) sh -c 'mkdir -p bin && go build -trimpath -ldflags "$(LDFLAGS)" -o bin/simple-siem ./cmd/simple-siem'

run: build
	$(RUN) $(TOOLCHAIN_IMAGE) ./bin/simple-siem $(ARGS)

dev: postgres $(TOOLCHAIN_STAMP)
	$(RUN) --name $(DEV_CONTAINER) $(TOOLCHAIN_IMAGE) air -c .air.toml

db-shell: postgres
	$(CONTAINER) run --rm -i --network $(NETWORK) --env-file $(POSTGRES_ENV_FILE) $(POSTGRES_IMAGE) sh -c 'PGPASSWORD="$$POSTGRES_PASSWORD" exec psql -h $(POSTGRES_HOST) -U "$$POSTGRES_USER" -d "$$POSTGRES_DB"'

down:
	@$(CONTAINER) stop $(POSTGRES_CONTAINER) $(DEV_CONTAINER) 2>/dev/null || true

clean:
	@$(CONTAINER) rm -f $(POSTGRES_CONTAINER) $(DEV_CONTAINER) 2>/dev/null || true
	@$(CONTAINER) network rm $(NETWORK) 2>/dev/null || true
	@$(CONTAINER) volume rm $(POSTGRES_VOLUME) $(GO_MOD_CACHE_VOLUME) $(GO_BUILD_CACHE_VOLUME) 2>/dev/null || true
	rm -rf bin .make
