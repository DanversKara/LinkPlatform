#!/usr/bin/env bash
# Back up the LinkPlatform data volume to a timestamped tarball.
# Usage: backup.sh [install-dir]   (default: $HOME/linkplatform)
set -euo pipefail

LP_DIR="${1:-${LP_DIR:-$HOME/linkplatform}}"
[ -d "$LP_DIR" ] || { echo "ERROR: install dir not found: $LP_DIR" >&2; exit 1; }

# shellcheck disable=SC2086
if docker compose version >/dev/null 2>&1; then CC="docker compose";
elif command -v docker-compose >/dev/null 2>&1; then CC="docker-compose";
else echo "ERROR: docker compose not found" >&2; exit 1; fi

echo "Checkpointing the SQLite database..."
( cd "$LP_DIR" && $CC exec -T app python -c \
    "import asyncio; from app.db import backup_checkpoint; asyncio.run(backup_checkpoint())" )

DEST="$LP_DIR/backups"
mkdir -p "$DEST"
TS="$(date +%Y%m%d-%H%M%S)"
NAME="linkplatform-backup-${TS}.tar.gz"
FILE="$DEST/$NAME"

echo "Archiving data volume -> $FILE"
docker run --rm \
    -v linkplatform_data:/data:ro \
    -v "$DEST:/backup" \
    alpine tar czf "/backup/$NAME" -C /data .

echo "Pruning old backups (keeping newest 10)..."
# shellcheck disable=SC2012
ls -t "$DEST"/linkplatform-backup-*.tar.gz 2>/dev/null | tail -n +11 | xargs -r rm -f || true

echo "Backup complete: $FILE"
