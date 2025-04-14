#!/bin/sh
set -eu

GO_MAJOR_VER=1.22
GO_VERSION=1.22.9 # also update .github/workflows/tests.yml

# Pin Go and toolchain versions at a reasonable version
go get go@$GO_VERSION toolchain@$GO_VERSION

# Generate source
go generate -x ./cmd/... ./internal/...

# Reformat source
go run golang.org/x/tools/cmd/goimports@latest -w ./internal ./cmd
go fmt ./cmd/... ./internal/...

# Update go.mod and go.sum (keep it as the last)
go mod tidy
