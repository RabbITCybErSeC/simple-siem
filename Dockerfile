FROM --platform=$BUILDPLATFORM node:26.13.1-bookworm@sha256:b7087bc4d973034b30854b378ba107f9fab622b47514cb7e2592e41b8bab8d49 AS node

FROM --platform=$BUILDPLATFORM golang:1.27.4-bookworm AS toolchain

ARG GOLANGCI_LINT_VERSION=v2.15.0
ARG GOOSE_VERSION=v3.30.0
ARG AIR_VERSION=v1.67.4
ARG PNPM_VERSION=12.18.0

COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=node /usr/local/lib/node_modules /usr/local/lib/node_modules

RUN ln -s ../lib/node_modules/npm/bin/npm-cli.js /usr/local/bin/npm \
 && ln -s ../lib/node_modules/npm/bin/npx-cli.js /usr/local/bin/npx \
 && npm install --global --no-fund --no-audit pnpm@${PNPM_VERSION} \
 && go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_LINT_VERSION} \
 && go install github.com/pressly/goose/v3/cmd/goose@${GOOSE_VERSION} \
 && go install github.com/air-verse/air@${AIR_VERSION}

WORKDIR /src

FROM toolchain AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown

COPY go.* ./
COPY cmd/ ./cmd/
COPY internal/ ./internal/

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
    -ldflags "-X github.com/RabbITCybErSeC/simple-siem/internal/version.Version=${VERSION} -X github.com/RabbITCybErSeC/simple-siem/internal/version.Commit=${COMMIT}" \
    -o /simple-siem ./cmd/simple-siem

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS runtime

COPY --from=build /simple-siem /simple-siem

ENTRYPOINT ["/simple-siem"]

