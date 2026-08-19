```
████████╗██████╗  █████╗  ██████╗███████╗
╚══██╔══╝██╔══██╗██╔══██╗██╔════╝██╔════╝
   ██║   ██████╔╝███████║██║     █████╗
   ██║   ██╔══██╗██╔══██║██║     ██╔══╝
   ██║   ██║  ██║██║  ██║╚██████╗███████╗
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚══════╝
 ███████╗██╗     ███████╗██╗   ██╗████████╗██╗  ██╗
 ██╔════╝██║     ██╔════╝██║   ██║╚══██╔══╝██║  ██║
 ███████╗██║     █████╗  ██║   ██║   ██║   ███████║
 ╚════██║██║     ██╔══╝  ██║   ██║   ██║   ██╔══██║
 ███████║███████╗███████╗╚██████╔╝   ██║   ██║  ██║
 ╚══════╝╚══════╝╚══════╝ ╚═════╝    ╚═╝   ╚═╝  ╚═╝
```

# TraceSleuth

An agent runs bpftrace-based investigations on a host; at any point later a human
can answer, with zero ambiguity:

- What hypothesis was being tested?
- What exact eBPF script was loaded, on which host, by whom?
- What did policy decide, and why?
- What happened when it ran — duration, exit code, output?

**Traceability is the product, not a side feature.** Every meaningful step is
written to an append-only, hash-chained JSONL log (the source of truth); a SQLite
index is a disposable projection rebuilt from it for fast queries.

## Status

Single-host core works and is driveable over MCP. Investigations open, run
policy-gated probes, and close with a recap card naming the environment they ran
on; every step is on the hash chain. A long-lived `tracesleuthd` owns the data and
exposes `/metrics`; agents reach it over a Unix socket through an ephemeral relay.
Identity comes from the transport (SSH today, mTLS coded), never from the client.

Not built yet: baselines (async diffs), Kubernetes deployment, cgroup resource
guards. See [`docs/status.md`](docs/status.md) for the phase-by-phase state.

## How it runs

```
agent ──ssh──▶ tracesleuth-mcp -connect …   (ephemeral, runs as the ssh user)
                        │ Unix socket (SO_PEERCRED = identity)
                        ▼
                 tracesleuthd (systemd, user: tracesleuth)
                 ├─ /var/lib/tracesleuth      JSONL audit log + SQLite index
                 ├─ sudo → /usr/bin/bpftrace  scoped — the only privilege
                 └─ 127.0.0.1:9464            /healthz, /metrics
```

The agent never runs the daemon or bpftrace directly. It speaks MCP to the relay,
which forwards to the socket; the daemon attributes the work to the ssh user's
kernel-attested uid, so a client can't claim to be someone else. The MCP surface
is the intended interface — `list_probe_catalog`, `open_investigation`,
`preview_probe`, `run_probe`, `list_kernel_probes`, `close_investigation`,
`show_investigation`. See [`docs/mcp.md`](docs/mcp.md).

## Try it without a host (mock)

bpftrace needs Linux and root. To exercise the full open→probe→close flow and the
hash chain on any machine, set `TRACESLEUTH_EXECUTOR=mock`: the audit log records
that the mock ran, so a mock result is never mistaken for a real capture.

```sh
go build -o bin/tracectl ./cmd/tracectl
go build -o bin/verify-chain ./cmd/verify-chain

export TRACESLEUTH_EXECUTOR=mock

INV=$(bin/tracectl open --identity you@example --host $(hostname))
bin/tracectl hypothesis --inv $INV --text "tcp_connect latency correlates with openat storms"
bin/tracectl probe --inv $INV --type kprobe,kretprobe --attach tcp_connect \
    --duration 10 --script-file examples/tcp_latency.bt
bin/tracectl close --inv $INV --conclusion "confirmed"

bin/tracectl show --inv $INV     # reconstruct the whole chain from the index
bin/tracectl verify --all        # confirm the hash chain is intact
```

`scripts/demo.sh` runs the entire flow (including a probe policy denies) and
`scripts/tamper_test.sh` proves the chain detects edits and deletions. Requires Go
1.25+.

## Deploy on a host

`deploy/install.sh` builds the binaries, creates the `tracesleuth` system user,
installs the systemd unit and the scoped sudoers rule, and starts the service.
Full walkthrough — connecting an agent, configuration, metrics, uninstall — in
[`deploy/README.md`](deploy/README.md). Copy `.mcp.json.example` to `.mcp.json`
and edit it for your host.

Running real bpftrace needs a passwordless sudo rule scoped to exactly that
binary; the installer sets it up, and nothing else is elevated:

```
tracesleuth ALL=(root) NOPASSWD: /usr/bin/bpftrace
```

## What's here

| Component | Package | Role |
|---|---|---|
| Audit contract | `internal/event` | JSONL events, hash chain, verifier |
| Policy | `internal/policy` + `policy/*.rego` | allow-list, duration, aggregation & scoping rules |
| Probe catalog | `internal/catalog` | single source for what's allowed / high-frequency |
| Execution | `internal/exec` | `Executor` iface: real bpftrace (Linux) or mock |
| Index | `internal/store` | SQLite projection, rebuildable from JSONL |
| Orchestration | `internal/service` | hypothesis → probe → policy → result flow |
| Transport/identity | `internal/transport` | `IdentityResolver`: SSH + mTLS, one CA |
| Daemon | `cmd/tracesleuthd` | long-lived owner of the data; MCP over UDS, `/metrics` |
| MCP server | `cmd/tracesleuth-mcp` | agent-facing tools over stdio JSON-RPC; relay or in-process |
| CLIs | `cmd/tracectl`, `cmd/verify-chain` | drive investigations; verify the chain |

## Docs

- [`docs/architecture.md`](docs/architecture.md) — the design, end to end.
- [`docs/mcp.md`](docs/mcp.md) — driving it from an agent over MCP.
- [`docs/status.md`](docs/status.md) — honest phase-by-phase state.
- [`deploy/README.md`](deploy/README.md) — standalone host deployment.
- [`deploy/policy/README.md`](deploy/policy/README.md) — the on-disk policy/catalog and posture.
- [`deploy/teleport/README.md`](deploy/teleport/README.md) — the Teleport (`tsh`) transport.
- [`SECURITY.md`](SECURITY.md) — threat model and the privilege boundary.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — build, test, and the house style.

## Development

```sh
go test ./...          # unit + end-to-end (mock) tests
opa test ./policy/...  # policy correctness — safety-critical, required in CI
opa fmt --list policy/ # policy formatting
```

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`SECURITY.md`](SECURITY.md).
