#!/usr/bin/env bash
#
# Run HART-IP integration tests in Docker: FieldComm hipserver (v1),
# hipserver with TLS-PSK (v2) and the pure-Python mock.
#
# Usage:
#   ./tests/integration/run.sh          # build, start, test, stop
#   ./tests/integration/run.sh --keep   # keep containers after tests
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="${SCRIPT_DIR}/docker-compose.yml"
CONTAINERS=(hartip-test-device hartip-test-device-tls hartip-test-pymock)

KEEP=false
[[ "${1:-}" == "--keep" ]] && { KEEP=true; shift; }

# ── helpers ────────────────────────────────────────────────────────────

cleanup() {
    if [ "$KEEP" = false ]; then
        echo ">>> Stopping containers..."
        docker compose -f "$COMPOSE_FILE" down --timeout 5 2>/dev/null || true
    else
        echo ">>> Containers kept running (use: docker compose -f $COMPOSE_FILE down)"
    fi
}
trap cleanup EXIT

wait_for_port() {
    local host=$1 port=$2 timeout=${3:-30}
    echo -n "    Waiting for ${host}:${port}"
    for _ in $(seq 1 "$timeout"); do
        if nc -zu "$host" "$port" 2>/dev/null; then
            echo " OK"
            return 0
        fi
        echo -n "."
        sleep 1
    done
    echo " TIMEOUT"
    return 1
}

# ── preflight ──────────────────────────────────────────────────────────

echo ">>> Preflight checks"
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found"; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "ERROR: docker compose not found"; exit 1; }

# ── build ──────────────────────────────────────────────────────────────

echo ">>> Building containers..."
docker compose -f "$COMPOSE_FILE" build

# ── start ──────────────────────────────────────────────────────────────

echo ">>> Starting containers..."
docker compose -f "$COMPOSE_FILE" up -d

echo ">>> Waiting for HART-IP services..."
wait_for_port 127.0.0.1 5094 45    # hipserver, UDP and TCP on one port
wait_for_port 127.0.0.1 5095 45    # hipserver -psk
wait_for_port 127.0.0.1 25094 45   # pure-Python mock

# Extra settle time for hipserver init
sleep 2

# Verify containers are running
for name in "${CONTAINERS[@]}"; do
    if ! docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null | grep -q true; then
        echo "ERROR: Container $name is not running"
        docker logs "$name" 2>&1 | tail -20
        exit 1
    fi
done

echo ">>> Containers ready"

# ── test ───────────────────────────────────────────────────────────────

echo ">>> Running integration tests..."
cd "$(dirname "$SCRIPT_DIR")/.."  # project root

python -m pytest tests/integration/ \
    -m integration \
    -v \
    --tb=short \
    -x \
    "$@"
