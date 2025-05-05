#!/bin/bash
set -euxo pipefail

function greenprint {
    echo -e "\033[1;32m[$(date -Isecond)] ${1}\033[0m"
}

greenprint "Building test container"
sudo podman build --label="quay.expires-after=1w" --security-opt "label=disable" -t image-builder-crc -f distribution/Dockerfile-ubi .

greenprint "Pulling osbuild/postgres:13-alpine"
sudo podman pull docker://quay.io/osbuild/postgres:13-alpine

greenprint "Starting image-builder-db"
sudo podman run -p 5432:5432 --name image-builder-db \
      --health-cmd "pg_isready -U postgres -d imagebuilder" --health-interval 2s \
      --health-timeout 2s --health-retries 10 \
      -e POSTGRES_USER=postgres \
      -e POSTGRES_PASSWORD=foobar \
      -e POSTGRES_DB=imagebuilder \
      -d postgres

for RETRY in {1..10}; do
    if sudo podman healthcheck run image-builder-db  > /dev/null 2>&1; then
       break
    fi
    echo "Retrying in 2 seconds... $RETRY"
    sleep 2
done

greenprint "Migrate image-builder-db"
sudo podman run --pull=never --security-opt "label=disable" --net=host \
     -e PGHOST=localhost -e PGPORT=5432 -e PGDATABASE=imagebuilder \
     -e PGUSER=postgres -e PGPASSWORD=foobar \
     --name image-builder-migrate \
     --entrypoint /app/image-builder-migrate-db-tern \
     image-builder-crc
sudo podman logs image-builder-migrate

greenprint "Run image-builder-crc container"
echo "{\"000000\":{\"quota\":5,\"slidingWindow\":1209600000000000},\"000001\":{\"quota\":0,\"slidingWindow\":1209600000000000}}" > /tmp/quotas
sudo podman run -d --pull=never --security-opt "label=disable" --net=host \
     -e COMPOSER_URL=https://api.stage.openshift.com: \
     -e COMPOSER_TOKEN_URL="https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token" \
     -e COMPOSER_CLIENT_SECRET="${COMPOSER_CLIENT_SECRET:-}" \
     -e COMPOSER_CLIENT_ID="${COMPOSER_CLIENT_ID:-}" \
     -e OSBUILD_AWS_REGION="${AWS_REGION:-}" \
     -e OSBUILD_GCP_REGION="${GCP_REGION:-}" \
     -e OSBUILD_GCP_BUCKET="${GCP_BUCKET:-}" \
     -e CONTENT_SOURCES_URL="http://127.0.0.1:10000" \
     -e PGHOST=localhost -e PGPORT=5432 -e PGDATABASE=imagebuilder \
     -e PGUSER=postgres -e PGPASSWORD=foobar \
     -e ALLOWED_ORG_IDS="000000" \
     -e DISTRIBUTIONS_DIR="/app/distributions" \
     -e QUOTA_FILE="/app/accounts_quotas.json" \
     -v /tmp/quotas:/app/accounts_quotas.json \
     --name image-builder \
     image-builder-crc
