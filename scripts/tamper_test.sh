#!/usr/bin/env bash
# Proves the audit chain detects both content tampering and line deletion.
set -uo pipefail
cd "$(dirname "$0")/.."
F=$(ls data/logs/*.jsonl | head -1)
echo "file: $F"
echo; echo "--- verify pristine ---"
./bin/verify-chain "$F"

echo; echo "--- tamper: rewrite conclusion in place, leave hash field untouched ---"
cp "$F" data/logs/_tampered.jsonl
sed -i 's/log rotation/DISK FAILURE/' data/logs/_tampered.jsonl
./bin/verify-chain data/logs/_tampered.jsonl
echo "verify_exit=$?"

echo; echo "--- delete a middle line, verify seq-gap detection ---"
sed '4d' "$F" > data/logs/_deleted.jsonl
./bin/verify-chain data/logs/_deleted.jsonl
echo "verify_exit=$?"
rm -f data/logs/_tampered.jsonl data/logs/_deleted.jsonl
