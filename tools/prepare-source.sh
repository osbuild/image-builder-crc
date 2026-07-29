#!/bin/sh
set -eu

GO_VERSION=1.26.5 # also update .github/workflows/tests.yml

# Pin Go and toolchain versions at a reasonable version
go get go@$GO_VERSION toolchain@$GO_VERSION
go mod tidy

# Generate source
go generate -x ./cmd/... ./internal/...

# Update go.mod and go.sum
go mod tidy

# Reformat source
go run golang.org/x/tools/cmd/goimports@latest -w ./internal ./cmd
go fmt ./cmd/... ./internal/...
