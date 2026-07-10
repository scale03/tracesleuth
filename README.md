# TraceSleuth

An internal tool where an agent runs bpftrace-based investigations, and at any
point later a human can answer, with zero ambiguity:

- What hypothesis was being tested?
- What exact eBPF script was loaded, on which host, by whom?
- What did policy decide, and why?
- What happened when it ran — duration, exit code, output?

**Traceability is the product, not a side feature.** Every meaningful step is
written to an append-only, hash-chained JSONL log (the source of truth); a
SQLite index is a disposable projection rebuilt from it for fast queries.

Status: **single-host core working** — Phases 0, 1, 3 (embedded policy), 6, plus
output-shaping and the discovery catalog. Teleport transport (Phase 2) and async
baselines (Phase 7) are designed but not yet built. See
[`docs/architecture.md`](docs/architecture.md) for the full picture and
[`docs/status.md`](docs/status.md) for the phase-by-phase state.

## What's here

| Component | Package | Role |
|---|---|---|
| Audit contract | `internal/event` | JSONL events, hash chain, verifier |
| Policy | `internal/policy` + `policy/*.rego` | allow-list, duration, aggregation & scoping rules |
| Probe catalog | `internal/catalog` | single source for what's allowed / high-frequency |
| Execution | `internal/exec` | `Executor` iface: real bpftrace (Linux) or mock |
| Index | `internal/store` | SQLite projection, rebuildable from JSONL |
| Orchestration | `internal/service` | hypothesis → probe → policy → result flow |
| CLIs | `cmd/tracectl`, `cmd/verify-chain` | drive investigations; verify the chain |

## Quickstart (single host)

Requires Go 1.25+. bpftrace runs only on Linux and needs root; on any other host
(or before you wire up sudo) set `TRACESLEUTH_EXECUTOR=mock` to use the
deterministic fake backend — the audit log records that the mock ran, so a mock
result is never mistaken for a real capture.

```sh
go build -o bin/tracectl ./cmd/tracectl
go build -o bin/verify-chain ./cmd/verify-chain

export TRACESLEUTH_EXECUTOR=mock          # omit on a Linux host with real bpftrace

INV=$(bin/tracectl open --identity you@example --host $(hostname))
bin/tracectl hypothesis --inv $INV --text "tcp_connect latency correlates with openat storms"
bin/tracectl probe --inv $INV --type kprobe,kretprobe --attach tcp_connect \
    --duration 10 --script-file examples/tcp_latency.bt
bin/tracectl close --inv $INV --conclusion "confirmed"

bin/tracectl show --inv $INV     # reconstruct the whole chain from the index
bin/tracectl verify --all        # confirm the hash chain is intact
```

`scripts/demo.sh` runs the entire flow (including a probe that policy denies) and
`scripts/tamper_test.sh` proves the chain detects edits and deletions.

### Running real bpftrace (Linux)

bpftrace requires root. Grant a scoped, passwordless sudo rule for exactly that
binary — nothing else is elevated:

```sh
echo 'YOURUSER ALL=(root) NOPASSWD: /usr/bin/bpftrace' | sudo tee /etc/sudoers.d/tracesleuth
sudo chmod 440 /etc/sudoers.d/tracesleuth
```

Then run without `TRACESLEUTH_EXECUTOR=mock`; the daemon auto-selects the real
bpftrace backend when the binary is present.

## Development

```sh
go test ./...          # unit + end-to-end (mock) tests
opa test ./policy/...  # policy correctness — safety-critical, required in CI
opa fmt --list policy/ # policy formatting
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`SECURITY.md`](SECURITY.md).
