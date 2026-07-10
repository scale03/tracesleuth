#!/usr/bin/env bash
# End-to-end demo: opens an investigation, runs one allowed (aggregated) probe
# and one denied (high-frequency, unaggregated) probe, closes it, then shows the
# reconstructed chain and verifies the audit hash chain.
#
# Set TRACESLEUTH_EXECUTOR=mock to use the fake backend (no root needed).
# Leave it unset on Linux with passwordless sudo for bpftrace to run for real.
set -uo pipefail
cd "$(dirname "$0")/.."

B=./bin/tracectl
HOST="${HOST:-$(hostname)}"
rm -rf data

echo "===== CATALOG ====="
$B catalog

echo; echo "===== OPEN ====="
INV=$($B open --identity teleport-bot:agent-x --roles reliability-team --host "$HOST")
echo "investigation: $INV"
$B hypothesis --inv "$INV" --text 'tcp_connect latency spike correlates with openat() storms'

echo; echo "===== PROBE 1 — allowed (aggregated histogram) ====="
$B probe --inv "$INV" --type kprobe,kretprobe --attach tcp_connect --duration 10 \
   --script-file examples/tcp_latency.bt

echo; echo "===== PROBE 2 — expected DENY (high-frequency, no aggregation) ====="
$B probe --inv "$INV" --type tracepoint --attach sys_enter_read --filter-pid \
   --script-file examples/read_flood.bt
echo "(denied probe exit code: $?)"

echo; echo "===== CLOSE ====="
$B close --inv "$INV" --conclusion 'confirmed: openat() storm from log rotation causes the latency spike'

echo; echo "===== SHOW (reconstructed from SQLite index) ====="
$B show --inv "$INV"

echo; echo "===== VERIFY (hash chain) ====="
$B verify --all
