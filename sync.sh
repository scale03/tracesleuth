#!/usr/bin/env bash
set -euo pipefail
HOST="${1:-ale@192.168.1.23}"
DEST="${2:-/home/ale/tracesleuth}"
rsync -az --delete \
  --exclude 'TraceSleuth.md' --exclude '.git' --exclude 'data/' \
  --exclude 'outputs/' --exclude '*.db' --exclude 'sync.sh' \
  --exclude 'bin/' \
  ./ "$HOST:$DEST/"
echo "synced -> $HOST:$DEST"
