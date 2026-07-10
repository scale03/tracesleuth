#!/usr/bin/env bash
# Drives the MCP server over stdio with a scripted JSON-RPC session, exercising
# the initialize handshake, tools/list, and a full investigation via tool calls.
# Uses the mock executor so it runs without root.
set -uo pipefail
cd "$(dirname "$0")/.."
rm -rf data

REQS=$(cat <<'JSON'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"list_probe_catalog","arguments":{}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"open_investigation","arguments":{"hypothesis":"tcp_connect latency spikes under load","identity":"claude-agent"}}}
JSON
)

# Run phase 1: get the investigation id from the open_investigation result.
OUT1=$(printf '%s\n' "$REQS" | TRACESLEUTH_EXECUTOR=mock TRACESLEUTH_HOST=prod-web-12 ./bin/tracesleuth-mcp 2>/dev/null)
echo "=== initialize / tools/list / catalog / open ==="
echo "$OUT1"

INV=$(echo "$OUT1" | grep -o 'inv_[a-f0-9]\{8\}' | head -1)
echo; echo "extracted investigation id: $INV"

# Phase 2: run an allowed probe, a denied probe, show, verify, close.
REQS2=$(cat <<JSON
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{}}}
{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"run_probe","arguments":{"investigation_id":"$INV","script":"kprobe:tcp_connect { @start[tid]=nsecs; }\nkretprobe:tcp_connect { @lat=hist(nsecs-@start[tid]); delete(@start[tid]); }","probe_types":["kprobe","kretprobe"],"attach_points":["tcp_connect"],"duration_s":10}}}
{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"run_probe","arguments":{"investigation_id":"$INV","script":"tracepoint:syscalls:sys_enter_read { printf(\"%d\\n\", pid); }","probe_types":["tracepoint"],"attach_points":["sys_enter_read"],"filter_pid":true}}}
{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"close_investigation","arguments":{"investigation_id":"$INV","conclusion":"confirmed under load"}}}
{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"show_investigation","arguments":{"investigation_id":"$INV"}}}
{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"verify_investigation","arguments":{"investigation_id":"$INV"}}}
JSON
)
echo; echo "=== run_probe (allow) / run_probe (deny) / close / show / verify ==="
printf '%s\n' "$REQS2" | TRACESLEUTH_EXECUTOR=mock TRACESLEUTH_HOST=prod-web-12 ./bin/tracesleuth-mcp 2>/dev/null
