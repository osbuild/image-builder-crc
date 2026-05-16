# AGENTS

Image Builder CRC is an HTTP API middleware service that sits between the Image
Builder frontend and osbuild-composer.

Generated code is checked into version control. OpenAPI specs are in:

* `internal/v1/api.yaml` - main service API
* `internal/clients/*/` - client packages

Uses structured logging (slog). Log messages should be lowercase and static.
Prefer context-aware logging methods when context is available.

## Tests

Use `make unit-tests UNIT_TEST_ARGS=` to run all tests quickly.

Do not start the application with `make run` unless instructed to do so, it
requires manual configuration.

## Git

Before doing any `git commit`, you *must* run:

* `./tools/prepare-source.sh`
* `make unit-tests`
* `golangci-lint run` but check the version against
  `.github/workflows/tests.yml` and if the version does not match output only a
  warning and do not block the commit

Commit messages *must* be in the format of: `package: lower case up to 65 chars`
where `package` is the Go package that is being changed, or where majority of
changes are. In case of multiple packages being changed in one commit, use
`many` instead.

## References

In addition, read:

* HACKING.md
* README.md
