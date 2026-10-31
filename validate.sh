#!/usr/bin/env bash
# token-gate container contract test.
#
# Runs the image on this machine and checks the behaviour a Traefik forwardAuth
# consumer depends on: 204 + identity header for a good token, 401 for
# everything else, the ?token= fallback for clients that cannot set a header,
# and a refusal to start with no tokens configured.
set -euo pipefail

cd "$(dirname "$0")"

IMAGE="initialed85/token-gate:validate"
NAME="token-gate-validate-$$"
PORT="18095"
TOKEN="validate$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')"
FAILS=0

log() { echo "[validate] $*"; }
record() { log "FAIL: $*"; FAILS=$((FAILS + 1)); }

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

log "building $IMAGE"
docker build -q -t "$IMAGE" . >/dev/null

docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" -p "${PORT}:8080" \
  -e "API_TOKEN_VALIDATE_TEST=${TOKEN}" "$IMAGE" >/dev/null

for _ in $(seq 1 30); do
  code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 2 "http://127.0.0.1:${PORT}/healthz" || true)
  [ "$code" = "200" ] && break
  sleep 0.5
done

log "GET /healthz (no token, kubelet probe)"
code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "http://127.0.0.1:${PORT}/healthz")
[ "$code" = "200" ] || record "/healthz returned $code, want 200"

log "GET /check (no credential)"
headers=$(curl -s -D - -o /dev/null --max-time 5 "http://127.0.0.1:${PORT}/check")
code=$(printf '%s' "$headers" | head -1 | awk '{print $2}')
[ "$code" = "401" ] || record "/check without a credential returned $code, want 401"
printf '%s' "$headers" | grep -qi '^www-authenticate:' || record "401 must carry WWW-Authenticate"

log "GET /check (bearer)"
headers=$(curl -s -D - -o /dev/null --max-time 5 -H "authorization: Bearer ${TOKEN}" "http://127.0.0.1:${PORT}/check")
code=$(printf '%s' "$headers" | head -1 | awk '{print $2}')
[ "$code" = "204" ] || record "/check with bearer returned $code, want 204"
printf '%s' "$headers" | grep -qi '^x-auth-request-user: VALIDATE_TEST' || record "missing X-Auth-Request-User on success (Traefik forwards only listed headers)"

log "GET /check (x-api-key)"
code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -H "x-api-key: ${TOKEN}" "http://127.0.0.1:${PORT}/check")
[ "$code" = "204" ] || record "/check with x-api-key returned $code, want 204"

log "GET /check (?token= on the forwarded URI, the websocket/browser fallback)"
code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 \
  -H "x-forwarded-uri: /render?url=https%3A%2F%2Fexample.com&token=${TOKEN}" \
  "http://127.0.0.1:${PORT}/check")
[ "$code" = "204" ] || record "?token= on X-Forwarded-Uri returned $code, want 204"

log "GET /check (wrong token)"
code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -H "authorization: Bearer not-a-token-at-all-000000000000000000000000" "http://127.0.0.1:${PORT}/check")
[ "$code" = "401" ] || record "/check with a wrong token returned $code, want 401"

log "GET /nope"
code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "http://127.0.0.1:${PORT}/nope")
[ "$code" = "404" ] || record "unknown path returned $code, want 404"

log "POST /render (forwardAuth is method-agnostic: a form POST must get 204 too)"
code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 -X POST --data "url=https://example.com/" \
  -H "authorization: Bearer ${TOKEN}" -H "x-forwarded-uri: /render" \
  "http://127.0.0.1:${PORT}/check")
[ "$code" = "204" ] || record "POST /check returned $code, want 204"

log "startup with no tokens must refuse to run"
out=$(docker run --rm -e PORT=8080 "$IMAGE" 2>&1 || true)
printf '%s' "$out" | grep -qi "refusing to run a gate with no tokens" || record "started with no tokens: $out"

log "container logs (one line per decision, deny lines rate-limited)"
docker logs "$NAME" 2>&1 | sed -n '1,12p' | sed 's/^/[validate]   /'

if [ "$FAILS" -gt 0 ]; then
  log "${FAILS} check(s) failed"
  exit 1
fi
log "all checks passed"
