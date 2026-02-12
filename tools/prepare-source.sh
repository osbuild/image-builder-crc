#!/bin/sh
set -eu

GO_MAJOR_VER=1.24
GO_VERSION=1.24.12 # also update .github/workflows/tests.yml

# Check latest Go version for the minor we're using
LATEST=$(curl -s https://endoflife.date/api/go/"${GO_MAJOR_VER}".json  | jq -r .latest)
if test "$LATEST" != "$GO_VERSION"; then
    echo "WARNING: A new minor release is available (${LATEST}), consider bumping the project version (${GO_VERSION})"
fi

# Pin Go and toolchain versions at a reasonable version
go get go@$GO_VERSION toolchain@$GO_VERSION

# Generate source
go generate -x ./cmd/... ./internal/...

# Reformat source
go run golang.org/x/tools/cmd/goimports@latest -w ./internal ./cmd
go fmt ./cmd/... ./internal/...

# Update go.mod and go.sum (keep it as the last)
go mod tidy
