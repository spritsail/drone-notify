#!/bin/sh
set -e

# ANSI colour escape sequences
RED='\033[0;31m'
RESET='\033[0m'

error() { >&2 echo -e "${RED}Error: $@${RESET}"; exit 1; }

# $PLUGIN_WEBHOOK_URL $WEBHOOK_URL      webhook URL to call
# $PLUGIN_NOTIFY_TOKEN $NOTIFY_TOKEN    bearer token for webhook
# $PLUGIN_METHOD                        request method (default POST)
# $PLUGIN_CURL_OPTS                     extra curl options

REQ_METHOD="${PLUGIN_METHOD:-POST}"
WEBHOOK_URL="${WEBHOOK_URL:-$PLUGIN_WEBHOOK_URL}"
NOTIFY_TOKEN="${NOTIFY_TOKEN:-$PLUGIN_NOTIFY_TOKEN}"

[ -z "$WEBHOOK_URL" ] && error "Missing required 'webhook_url' argument"
[ -n "$NOTIFY_TOKEN" ] && AUTH_HEADER="Authorization: $NOTIFY_TOKEN"

payload="$(env | sed -n 's/^DRONE_//p' \
               | awk -F= '{ eq=index($0,"="); print tolower(substr($0,0,eq-1)) substr($0,eq) }' \
               | tr '\n' '\0' | xargs -0 jo)"

curl $PLUGIN_CURL_OPTS \
    -fsSL \
    --retry 20 \
    --max-time 10 \
    --retry-max-time 120 \
    --retry-connrefused \
    -X $REQ_METHOD \
    -H "Content-Type: application/json" \
    -H "$AUTH_HEADER" \
    -d "$payload" \
    $WEBHOOK_URL
