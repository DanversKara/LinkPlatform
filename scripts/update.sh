#!/usr/bin/env bash
# Update LinkPlatform: rebuild the app image, recreate containers, verify health.
# Data lives in the named volume and survives the rebuild.
# Usage: update.sh [install-dir]   (default: $HOME/linkplatform)
set -euo pipefail

LP_DIR="${1:-${LP_DIR:-$HOME/linkplatform}}"
[ -d "$LP_DIR" ] || { echo "ERROR: install dir not found: $LP_DIR" >&2; exit 1; }
cd "$LP_DIR"

prof=()
if [ -f .env ] && grep -Eq '^DOMAIN=[^[:space:]#]+' .env; then
    prof=(--profile edge)
fi

# shellcheck disable=SC2086
if docker compose version >/dev/null 2>&1; then CC="docker compose";
elif command -v docker-compose >/dev/null 2>&1; then CC="docker-compose";
else echo "ERROR: docker compose not found" >&2; exit 1; fi

echo "Rebuilding app image..."
$CC build app

echo "Recreating containers..."
$CC "${prof[@]}" up -d

PORT="$(grep -E '^APP_PORT=' .env 2>/dev/null | cut -d= -f2- || true)"
PORT="${PORT:-8000}"

echo "Waiting for a healthy app (up to 120s)..."
ok=0
for i in $(seq 1 120); do
    if curl -fsS -o /dev/null "http://127.0.0.1:${PORT}/api/health" 2>/dev/null; then
        ok=1; break
    fi
    sleep 1
done
if [ "$ok" -ne 1 ]; then
    echo "ERROR: app did not become healthy within 120s. Last logs:" >&2
    docker compose logs --tail=50 app >&2
    exit 1
fi

VER="$(curl -fsS "http://127.0.0.1:${PORT}/api/health" 2>/dev/null \
    | python3 -c "import json,sys; print(json.load(sys.stdin).get('version','unknown'))" 2>/dev/null || echo unknown)"
echo "App is healthy. Version: $VER"
echo "Update complete."
