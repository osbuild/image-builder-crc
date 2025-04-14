#!/bin/sh
set -eu

# Go version must be consistent with image-builder which uses UBI
# container that is typically few months behind
GO_VERSION=1.22.9
GO_BINARY=$(go env GOPATH)/bin/go$GO_VERSION

# see https://go.dev/doc/manage-install
go install golang.org/dl/go$GO_VERSION@latest
$GO_BINARY download

# Generate source
$GO_BINARY generate -x ./cmd/... ./internal/...

# Reformat source
$GO_BINARY run golang.org/x/tools/cmd/goimports@latest -w ./internal ./cmd
$GO_BINARY fmt ./cmd/... ./internal/...

# Update go.mod and go.sum (keep it as the last)
$GO_BINARY mod tidy
