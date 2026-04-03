# Image Builder contributing guide

Please refer to the [developer guide](https://www.osbuild.org/docs/developer-guide/index) to learn about our workflow, code style and more.

## Internal architecture

On startup the service loads distribution metadata from JSON files on disk,
connects to PostgreSQL, and creates HTTP clients for external services
(osbuild-composer, content-sources, provisioning, compliance,
recommendations). It then registers the Echo HTTP server with middleware
(identity extraction, request validation, prometheus metrics) and starts
listening.

```
 HTTP request
      │
      ▼
 Echo middleware          (identity extraction, request validation, logging)
      │
      ▼
 Handler layer            (internal/v1/handler*.go)
      │
      ├──▶ Distribution   (internal/distribution/) — in-memory, loaded from
      │    registry          distributions/*.json at startup
      │
      ├──▶ Database        (internal/db/) — PostgreSQL via pgx, migrations
      │                      managed by tern
      │
      └──▶ External        (internal/clients/) — osbuild-composer,
           clients           content-sources, provisioning, etc.
```

### Key internal packages

| Package | Purpose |
|---|---|
| `internal/v1` | API layer: OpenAPI spec (`api.yaml`), auto-generated types (`api.go`), Echo server setup, all HTTP handlers |
| `internal/distribution` | Loads and queries distribution JSON files — architectures, image types, repos, bootc images |
| `internal/db` | PostgreSQL operations (blueprints, composes) and tern migration files |
| `internal/config` | Maps environment variables to the `ImageBuilderConfig` struct |
| `internal/clients/*` | HTTP clients for each external service, most auto-generated from OpenAPI specs |
| `internal/common` | Shared helpers: pagination, allow-lists, pointers |
| `internal/oauth2` | OAuth2 token handling for service-to-service auth |
| `internal/tutils` | Test utilities (identity header helpers, DB setup) |

## Running the project locally

### Prerequisites

- Go 1.21+
- Podman or Docker (for PostgreSQL)

Install dev dependencies:

```sh
make dev-prerequisites
```

### 1. Create `local.env`

Create a `local.env` file in the repo root:

```sh
PGDATABASE=imagebuilder
PGHOST=localhost
PGPORT=5434
PGUSER=user
PGPASSWORD=password

TERN_EXECUTABLE=tern
TERN_MIGRATIONS_DIR=internal/db/migrations-tern/

COMPOSER_CLIENT_ID=1
COMPOSER_OFFLINE_TOKEN=1
COMPOSER_TOKEN_URL=http://localhost

DISTRIBUTIONS_DIR=distributions/
LOG_LEVEL=trace
LISTEN_ADDRESS=:8086
```

The fake `COMPOSER_*` values let you start the service without a real
osbuild-composer. You can test distribution listing, blueprints, and other
endpoints, but actual image builds will fail.

### 2. Start the PostgreSQL container

```sh
podman run --replace --name image-builder-db \
  -p 5434:5432 \
  -e POSTGRES_USER=user \
  -e POSTGRES_PASSWORD=password \
  -e POSTGRES_DB=imagebuilder \
  --health-cmd "pg_isready -U user -d imagebuilder" \
  --health-interval 10s --health-timeout 5s --health-retries 5 \
  -d postgres
```

Wait a few seconds for the container to become healthy.

### 3. Build

```sh
make build
```

### 4. Run database migrations

```sh
./image-builder-migrate-db-tern
```

### 5. Start the service

```sh
./image-builder
```

The API is now available at `http://localhost:8086/api/image-builder/v1/`.

### Identity header (`X-Rh-Identity`)

All API requests require a base64-encoded `X-Rh-Identity` JSON header. On
console.redhat.com this is injected by the platform. For local development
you must provide it yourself.

## Modifying the API

1. Edit `internal/v1/api.yaml` (the OpenAPI spec)
2. Run `make generate` to regenerate `internal/v1/api.go`
3. Update handler code in `internal/v1/handler*.go` as needed
4. Run `make push-check` before pushing

Never edit `api.go` by hand — it is overwritten on every `make generate`.

## Before pushing

Run `./tools/prepare-source.sh` (or `make prepare-source`) before pushing.
It regenerates code, reformats source, and tidies `go.mod`. CI runs the same
script and fails if anything changes, so running it locally avoids surprises.

## Symlinks and `distributions/` directory

Each subdirectory contains a JSON file describing a distribution's supported
architectures, image types, repositories, packages, and (optionally) bootc
images. The directory name **is** the distribution identifier used in the API.

**Symlinks** point major-version aliases to the latest GA minor release.
To see the current symlinks:

```sh
ls -l distributions/ | grep ^l
```

## Updating ./distributions

The files in `./distributions` are updated manually. When a new RHEL minor
release becomes generally available (GA), the previous release's directory is
copied and all references to the release version are updated. The symlink for
the major release is updated to point to the latest minor release.

Note that the repository keys do not change between minor releases and do not
require updating.

## Updating package lists

`tools/generate-package-lists` can be used in combination with a `distributions/`
file to generate a package list.

If the repository requires a client tls key/cert you can supply them with
`--key` and `--cert`.
