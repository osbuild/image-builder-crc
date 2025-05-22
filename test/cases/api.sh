#!/usr/bin/bash

#
# The image-builder API integration test
#
# This script sets `-x` and is meant to always be run like that. This is
# simpler than adding extensive error reporting, which would make this script
# considerably more complex. Also, the full trace this produces is very useful
# for the primary audience: developers of image-builder looking at the log
# from a run on a remote continuous integration system.
#

set -euxo pipefail

# Container image used for cloud provider CLI tools
CONTAINER_IMAGE_CLOUD_TOOLS="quay.io/osbuild/cloud-tools:latest"

if which podman 2>/dev/null >&2; then
  CONTAINER_RUNTIME=podman
elif which docker 2>/dev/null >&2; then
  CONTAINER_RUNTIME=docker
else
  echo No container runtime found, install podman or docker.
  exit 2
fi

############### Cleanup functions ################

function cleanupAWS() {
  # since this function can be called at any time, ensure that we don't expand unbound variables
  AWS_CMD="${AWS_CMD:-}"
  AWS_INSTANCE_ID="${AWS_INSTANCE_ID:-}"
  AMI_IMAGE_ID="${AMI_IMAGE_ID:-}"
  AWS_SNAPSHOT_ID="${AWS_SNAPSHOT_ID:-}"

  if [ -n "$AWS_CMD" ]; then
    set +e
    $AWS_CMD ec2 terminate-instances --instance-ids "$AWS_INSTANCE_ID"
    $AWS_CMD ec2 delete-key-pair --key-name "key-for-$AMI_IMAGE_ID"
    set -e
  fi
}

# Create a temporary directory and ensure it gets deleted when this script
# terminates in any way.
WORKDIR=$(mktemp -d)
KILL_PIDS=()
function cleanup() {
  cleanupAWS

  for P in "${KILL_PIDS[@]}"; do
      sudo kill "$P"
  done

  sudo rm -rf "$WORKDIR"
}
trap cleanup EXIT

# Content sources needs a little mock
cat > "/tmp/cs-mock.py" <<EOF
import json
from http.server import HTTPServer, BaseHTTPRequestHandler

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({'data': [], 'links': {}, 'meta': {}}).encode('utf-8'))


httpd = HTTPServer(("localhost", 10000), Handler)
httpd.serve_forever()
EOF
python3 /tmp/cs-mock.py &
KILL_PIDS+=("$!")

############### Common functions and variables ################

ACCOUNT0_ORG0='{"entitlements":{"rhel":{"is_entitled":true},"insights":{"is_entitled":true},"smart_management":{"is_entitled":true},"openshift":{"is_entitled":true},"hybrid":{"is_entitled":true},"migrations":{"is_entitled":true},"ansible":{"is_entitled":true}},"identity":{"account_number":"000000","type":"User","user":{"username":"user","email":"user@user.user","first_name":"user","last_name":"user","is_active":true,"is_org_admin":true,"is_internal":true,"locale":"en-US"},"internal":{"org_id":"000000"}}}'
ACCOUNT1_ORG1='{"entitlements":{"rhel":{"is_entitled":true},"insights":{"is_entitled":true},"smart_management":{"is_entitled":true},"openshift":{"is_entitled":true},"hybrid":{"is_entitled":true},"migrations":{"is_entitled":true},"ansible":{"is_entitled":true}},"identity":{"account_number":"000001","type":"User","user":{"username":"user","email":"user@user.user","first_name":"user","last_name":"user","is_active":true,"is_org_admin":true,"is_internal":true,"locale":"en-US"},"internal":{"org_id":"000001"}}}'

ACCOUNT0_ORG0=$(echo "$ACCOUNT0_ORG0" | base64 -w 0)
ACCOUNT1_ORG1=$(echo "$ACCOUNT1_ORG1" | base64 -w 0)

PORT="8086"
CURLCMD='curl -w %{http_code}'
HEADER="x-rh-identity: $ACCOUNT0_ORG0"
HEADER2="x-rh-identity: $ACCOUNT1_ORG1"
ADDRESS="localhost"
BASEURL="http://$ADDRESS:$PORT/api/image-builder/v1.0"
BASEURLMAJORVERSION="http://$ADDRESS:$PORT/api/image-builder/v1"
REQUEST_FILE="${WORKDIR}/request.json"
ARCH=$(uname -m)

DISTRO="rhel-8"
SSH_USER="ec2-user"

if [[ "$ARCH" == "x86_64" ]]; then
    INSTANCE_TYPE="t2.micro"
elif [[ "$ARCH" == "aarch64" ]]; then
    INSTANCE_TYPE="t4g.small"
else
  echo "Architecture not supported: $ARCH"
  exit 1
fi

# Wait until service is ready
READY=0
for RETRY in {1..10};do
  curl --fail -H "$HEADER" "http://$ADDRESS:$PORT/ready" && {
    READY=1
    break
  }
  echo "Port $PORT is not open. Waiting...($RETRY/10)"
  sleep 1
done

[ "$READY" -eq 1 ] || {
  echo "Port $PORT is not open after retrying 10 times. Exit."
  exit 1
}

function getResponse() {
  read -r -d '' -a ARR <<<"$1"
  echo "${ARR[@]::${#ARR[@]}-1}"
}

function getExitCode() {
  read -r -d '' -a ARR <<<"$1"
  echo "${ARR[-1]}"
}

function instanceWaitSSH() {
  local HOST="$1"

  for LOOP_COUNTER in {0..30}; do
      if ssh-keyscan "$HOST" > /dev/null 2>&1; then
          echo "SSH is up!"
          break
      fi
      echo "Retrying in 5 seconds... $LOOP_COUNTER"
      sleep 5
  done
}

function instanceCheck() {
  echo "✔️ Instance checking"
  local _ssh="$1"
  local _testModuleHotfixes="${2:-0}"

  # Check if postgres is installed
  $_ssh rpm -q postgresql ansible-core

  # Check if nginx was installed
  if [[ "$_testModuleHotfixes" == "1" ]]; then
      $_ssh rpm -q nginx nginx-module-njs
  fi

  # Verify subscribe status. Loop check since the system may not be registered such early
  set +eu
  for LOOP_COUNTER in {1..10}; do
      subscribe_org_id=$($_ssh sudo subscription-manager identity | grep 'org ID')
      if [[ "$subscribe_org_id" == "org ID: $API_TEST_SUBSCRIPTION_ORG_ID" ]]; then
          echo "System is subscribed."
          break
      else
          echo "System is not subscribed. Retrying in 30 seconds...($LOOP_COUNTER/10)"
          sleep 30
      fi
  done
  set -eu
  [[ "$subscribe_org_id" == "org ID: $API_TEST_SUBSCRIPTION_ORG_ID" ]]

  # Unregister subscription (try one more time if it fails)
  $_ssh sudo subscription-manager unregister || \
	(sleep 5 && $_ssh sudo subscription-manager unregister)
}

############### AWS-specific functions ################

function checkEnvAWS() {
  printenv AWS_REGION AWS_BUCKET V2_AWS_ACCESS_KEY_ID V2_AWS_SECRET_ACCESS_KEY AWS_API_TEST_SHARE_ACCOUNT > /dev/null
}

function installClientAWS() {
  if ! hash aws; then
    echo "Using 'awscli' from a container"
    sudo ${CONTAINER_RUNTIME} pull ${CONTAINER_IMAGE_CLOUD_TOOLS}

    AWS_CMD="sudo ${CONTAINER_RUNTIME} run --rm \
      -e AWS_ACCESS_KEY_ID=${V2_AWS_ACCESS_KEY_ID} \
      -e AWS_SECRET_ACCESS_KEY=${V2_AWS_SECRET_ACCESS_KEY} \
      -v ${WORKDIR}:${WORKDIR}:Z \
      ${CONTAINER_IMAGE_CLOUD_TOOLS} aws --region $AWS_REGION --output json --color on"
  else
    echo "Using pre-installed 'aws' from the system"
    AWS_CMD="env AWS_ACCESS_KEY_ID=$V2_AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY=$V2_AWS_SECRET_ACCESS_KEY aws --region $AWS_REGION --output json --color on"
  fi
  $AWS_CMD --version
}

function createReqFileAWS() {
  cat > "$REQUEST_FILE" << EOF
{
  "distribution": "$DISTRO",
  "client_id": "api",
  "image_requests": [
    {
      "architecture": "$ARCH",
      "image_type": "ami",
      "upload_request": {
        "type": "aws",
        "options": {
          "share_with_accounts": ["${AWS_API_TEST_SHARE_ACCOUNT}"]
        }
      }
    }
  ],
  "customizations": {
    "custom_repositories": [
      {
        "baseurl": [
          "http://nginx.org/packages/rhel/8/$ARCH/"
        ],
        "check_gpg": false,
        "id": "076119fc-2dbc-49d7-bbd7-b39ca2bc3086",
        "name": "nginx",
        "module_hotfixes": true
      }
    ],
    "packages": [
      "postgresql",
      "ansible-core",
      "nginx",
      "nginx-module-njs"
    ],
    "payload_repositories": [
      {
        "baseurl": "http://nginx.org/packages/rhel/8/$ARCH/",
        "check_gpg": false,
        "check_repo_gpg": false,
        "rhsm": false,
        "module_hotfixes": true
      }
    ],
    "subscription": {
      "organization": ${API_TEST_SUBSCRIPTION_ORG_ID:-},
      "activation-key": "${API_TEST_SUBSCRIPTION_ACTIVATION_KEY_V2:-}",
      "base-url": "https://cdn.redhat.com/",
      "server-url": "subscription.rhsm.redhat.com",
      "insights": true,
      "rhc": true
    }
  }
}
EOF
}

source /etc/os-release

############### Test cases definitions ################

### Case: get version
function Test_getVersion() {
  URL="$1"
  RESULT=$($CURLCMD -H "$HEADER" "$URL/version")
  V=$(getResponse "$RESULT" | jq -r '.version')
  [[ "$V" == "1.0" ]]
  EXIT_CODE=$(getExitCode "$RESULT")
  [[ "$EXIT_CODE" == 200 ]]
}

### Case: get openapi.json
function Test_getOpenapi() {
  URL="$1"
  RESULT=$($CURLCMD -H "$HEADER" "$URL/openapi.json")
  EXIT_CODE=$(getExitCode "$RESULT")
  [[ "$EXIT_CODE" == 200 ]]
}

### Case: post to composer
function Test_postToComposer() {
  RESULT=$($CURLCMD -H "$HEADER" -H 'Content-Type: application/json' --request POST --data @"$REQUEST_FILE" "$BASEURL/compose")
  EXIT_CODE=$(getExitCode "$RESULT")
  [[ "$EXIT_CODE" == 201 ]]
  COMPOSE_ID=$(getResponse "$RESULT" | jq -r '.id')
  [[ "$COMPOSE_ID" =~ ^\{?[A-F0-9a-f]{8}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{4}-[A-F0-9a-f]{12}\}?$ ]]
}

### Case: post to composer without enough quotas
function Test_postToComposerWithoutEnoughQuotas() {
  RESULT=$($CURLCMD -H "$HEADER2" -H 'Content-Type: application/json' --request POST --data @"$REQUEST_FILE" "$BASEURL/compose")
  EXIT_CODE=$(getExitCode "$RESULT")
  [[ "$EXIT_CODE" == 403 ]]
}

### Case: wait for the compose to finish successfully
function Test_waitForCompose() {
  while true
  do
    RESULT=$($CURLCMD -H "$HEADER" --request GET "$BASEURL/composes/$COMPOSE_ID")
    EXIT_CODE=$(getExitCode "$RESULT")
    [[ $EXIT_CODE == 200 ]]

    COMPOSE_STATUS=$(getResponse "$RESULT" | jq -r '.image_status.status')
    UPLOAD_STATUS=$(getResponse "$RESULT" | jq -r '.image_status.upload_status.status')

    case "$COMPOSE_STATUS" in
      # "running is kept here temporarily for backward compatibility"
      "running")
        ;;
      # valid status values for compose which is not yet finished
      "pending"|"building"|"uploading"|"registering")
        ;;
      "success")
        [[ "$UPLOAD_STATUS" = "success" ]]
        break
        ;;
      "failure")
          echo "Image compose failed, compose status response:"
          echo "$RESULT" | jq -r .
        exit 1
        ;;
      *)
        echo "API returned unexpected image_status.status value: '$COMPOSE_STATUS'"
        exit 1
        ;;
    esac

    sleep 30
  done
}

function Test_wrong_user_get_compose_status() {
  RESULT=$($CURLCMD -H "$HEADER2" --request GET "$BASEURL/composes/$COMPOSE_ID")
  EXIT_CODE=$(getExitCode "$RESULT")
  [[ $EXIT_CODE == 404 ]]
}

### Case: verify the result (image) of a finished compose in AWS
function Test_verifyComposeResultAWS() {
  UPLOAD_OPTIONS="$1"

  AMI_IMAGE_ID=$(echo "$UPLOAD_OPTIONS" | jq -r '.ami')
  # AWS ID consist of resource identifier followed by a 17-character string
  [[ "$AMI_IMAGE_ID" =~ ami-[[:alnum:]]{17} ]]

  local REGION
  REGION=$(echo "$UPLOAD_OPTIONS" | jq -r '.region')
  [[ "$REGION" = "$AWS_REGION" ]]

  # Tag image and snapshot with "gitlab-ci-test" tag
  $AWS_CMD ec2 create-tags \
    --resources "${AMI_IMAGE_ID}" \
    --tags Key=gitlab-ci-test,Value=true

  # Create key-pair
  $AWS_CMD ec2 create-key-pair --key-name "key-for-$AMI_IMAGE_ID" --query 'KeyMaterial' --output text > keypair.pem
  chmod 400 ./keypair.pem

  # Create an instance based on the ami
  $AWS_CMD ec2 run-instances --image-id "$AMI_IMAGE_ID" --count 1 --instance-type "$INSTANCE_TYPE" \
	  --key-name "key-for-$AMI_IMAGE_ID" \
	  --tag-specifications 'ResourceType=instance,Tags=[{Key=gitlab-ci-test,Value=true}]' > "$WORKDIR/instances.json"
  AWS_INSTANCE_ID=$(jq -r '.Instances[].InstanceId' "$WORKDIR/instances.json")

  $AWS_CMD ec2 wait instance-running --instance-ids "$AWS_INSTANCE_ID"

  $AWS_CMD ec2 describe-instances --instance-ids "$AWS_INSTANCE_ID" > "$WORKDIR/instances.json"
  HOST=$(jq -r '.Reservations[].Instances[].PublicIpAddress' "$WORKDIR/instances.json")

  echo "⏱ Waiting for AWS instance to respond to ssh"
  instanceWaitSSH "$HOST"

  # Verify image
  _ssh="ssh -oStrictHostKeyChecking=no -i ./keypair.pem $SSH_USER@$HOST"
  instanceCheck "$_ssh" "1"
}

### Case: verify the result (image) of a finished compose
function Test_verifyComposeResult() {
  RESULT=$($CURLCMD -H "$HEADER" --request GET "$BASEURL/composes/$COMPOSE_ID")
  EXIT_CODE=$(getExitCode "$RESULT")
  [[ $EXIT_CODE == 200 ]]

  UPLOAD_TYPE=$(getResponse "$RESULT" | jq -r '.image_status.upload_status.type')
  [[ "$UPLOAD_TYPE" = "aws" ]]

  UPLOAD_OPTIONS=$(getResponse "$RESULT" | jq -r '.image_status.upload_status.options')

  Test_verifyComposeResultAWS "$UPLOAD_OPTIONS"
}

### Case: verify the Software Bill of Materials (SBOMs) for a finished compose
function Test_verifyComposeSBOMs() {
  local RESULT
  # disable verbose shell output because the response is too long
  set +x
  RESULT=$($CURLCMD -H "$HEADER" --request GET "$BASEURL/composes/$COMPOSE_ID/sboms")
  EXIT_CODE=$(getExitCode "$RESULT")
  [[ $EXIT_CODE == 200 ]]

  local SBOMS
  SBOMS=$(getResponse "$RESULT" | jq -r '.data')
  if [[ $(echo "$SBOMS" | jq -r 'length') -ne 2 ]]; then
    set -x
    echo "SBOMs are not 2. Got response:"
    echo "$RESULT" | jq -r .
    exit 1
  fi

  # There should be 2 SBOMs: one for the 'image' and one for the 'buildroot'
  # Check the 'image' SBOM
  local SBOM_OS
  SBOM_OS=$(echo "$SBOMS" | jq -r '.[] | select(.pipeline_name == "os")')
  if [[ -z "$SBOM_OS" ]]; then
    set -x
    echo "SBOM for pipeline name 'os' not found. Got response:"
    echo "$RESULT" | jq -r .
    exit 1
  fi
  [[ $(echo "$SBOM_OS" | jq -r '.pipeline_purpose') == "image" ]]
  [[ $(echo "$SBOM_OS" | jq -r '.sbom_type') == "spdx" ]]
  # check if there is 'postgresql' in the sbom
  local SBOM_OS_PGSQL_PKG
  SBOM_OS_PGSQL_PKG=$(echo "$SBOM_OS" | jq -r '.sbom.packages[] | select(.name == "postgresql")')
  if [[ -z "$SBOM_OS_PGSQL_PKG" ]]; then
    set -x
    echo "'postgresql' not found in SBOM for pipeline name 'os'. Got response:"
    echo "$RESULT" | jq -r .
    exit 1
  fi

  # Check the 'buildroot' SBOM
  local SBOM_BUILD
  SBOM_BUILD=$(echo "$SBOMS" | jq -r '.[] | select(.pipeline_name == "build")')
  if [[ -z "$SBOM_BUILD" ]]; then
    set -x
    echo "SBOM for pipeline name 'build' not found. Got response:"
    echo "$RESULT" | jq -r .
    exit 1
  fi
  [[ $(echo "$SBOM_BUILD" | jq -r '.pipeline_purpose') == "buildroot" ]]
  [[ $(echo "$SBOM_BUILD" | jq -r '.sbom_type') == "spdx" ]]
  set -x
}

### Case: verify package list of a finished compose
function Test_verifyComposeMetadata() {
  local RESULT
  RESULT=$($CURLCMD -H "$HEADER" --request GET "$BASEURL/composes/$COMPOSE_ID/metadata")
  EXIT_CODE=$(getExitCode "$RESULT")
  [[ $EXIT_CODE == 200 ]]

  local PACKAGENAMES
  PACKAGENAMES=$(getResponse "$RESULT" | jq -r '.packages[].name')
  if ! grep -q postgresql <<< "${PACKAGENAMES}"; then
      echo "'postgresql' not found in compose package list 😠"
      exit 1
  fi
}

function Test_getComposes() {
  RESULT=$($CURLCMD -H "$HEADER" -H 'Content-Type: application/json' "$BASEURL/composes")
  EXIT_CODE=$(getExitCode "$RESULT")
  [[ "$EXIT_CODE" == 200 ]]
  RESPONSE=$(getResponse "$RESULT" | jq -r '.data[0]')
  [[ $(echo "$RESPONSE" | jq -r '.id') == "$COMPOSE_ID" ]]
  diff <(echo "$RESPONSE" | jq -Sr '.request') <(jq -Sr '.' "$REQUEST_FILE")
}

checkEnvAWS
installClientAWS
createReqFileAWS

############### Test begin ################
Test_getVersion "$BASEURL"
Test_getVersion "$BASEURLMAJORVERSION"
Test_getOpenapi "$BASEURL"
Test_getOpenapi "$BASEURLMAJORVERSION"
Test_postToComposer
Test_waitForCompose
Test_wrong_user_get_compose_status
Test_verifyComposeResult
Test_verifyComposeMetadata
Test_getComposes
Test_postToComposerWithoutEnoughQuotas
Test_verifyComposeSBOMs

echo "########## Test success! ##########"
exit 0
