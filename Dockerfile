FROM golang:1.27.4-bookworm AS toolchain

ARG GOLANGCI_LINT_VERSION=v2.15.0
ARG GOOSE_VERSION=v3.30.0
ARG AIR_VERSION=v1.67.4

RUN go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_LINT_VERSION} \
 && go install github.com/pressly/goose/v3/cmd/goose@${GOOSE_VERSION} \
 && go install github.com/air-verse/air@${AIR_VERSION}

WORKDIR /src
