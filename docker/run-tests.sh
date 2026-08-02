#!/usr/bin/env bash
#
# Runs the RFC 8705 test stack end to end: generates certificates, starts Keycloak,
# runs the tests against it and tears the stack down again.
#
#   ./docker/run-tests.sh          run the tests
#   ./docker/run-tests.sh --keep   leave Keycloak running afterwards
#
set -euo pipefail

cd "$(dirname "$0")/.."
COMPOSE="docker compose -f docker/docker-compose.yml"
KEEP=0
[ "${1:-}" = "--keep" ] && KEEP=1

cleanup() {
  if [ "$KEEP" -eq 0 ]; then
    echo "==> Tearing down"
    $COMPOSE down -v >/dev/null 2>&1 || true
  else
    echo "==> Keeping Keycloak running (https://localhost:8443, admin/admin)"
  fi
}
trap cleanup EXIT

echo "==> Generating certificates"
./docker/scripts/generate-certs.sh

echo "==> Starting Keycloak"
$COMPOSE up -d keycloak

echo "==> Waiting for Keycloak to become healthy"
for _ in $(seq 1 60); do
  status="$(docker inspect -f '{{.State.Health.Status}}' docker-keycloak-1 2>/dev/null || echo starting)"
  [ "$status" = "healthy" ] && break
  sleep 5
done
[ "${status:-}" = "healthy" ] || { echo "Keycloak did not become healthy"; $COMPOSE logs keycloak | tail -40; exit 1; }

echo "==> Running RFC 8705 tests"
$COMPOSE run --rm tests
