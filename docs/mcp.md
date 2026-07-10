# Using TraceSleuth via MCP

TraceSleuth is meant to be driven by an agent through the **Model Context
Protocol**. `cmd/tracesleuth-mcp` is a stdio JSON-RPC MCP server that exposes the
investigation surface as tools.

## Tools

| Tool | What it does |
|---|---|
| `list_probe_catalog` | allowed probe types / attach points, which are high-frequency, duration limits. Call first. |
| `open_investigation` | open + record hypothesis, returns `investigation_id`. |
| `run_probe` | dry-run + policy + run one probe; returns status, the echoed script, the decision, and a byte-capped output summary (full output saved to disk). A denial returns the actionable reason. |
| `close_investigation` | record the conclusion and close. |
| `show_investigation` | full reconstructed chain from the index. |
| `verify_investigation` | verify the tamper-evident hash chain. |

## Transport: where the server runs

bpftrace needs a Linux kernel, so the server runs **on the Linux host**, and the
MCP client launches it over SSH (stdio is piped through the SSH channel). This is
the SSH transport from the plan; `tsh ssh` is a drop-in replacement once Teleport
is in place (see below).

### Register with Claude Code

A project-scoped [`.mcp.json`](../.mcp.json) is included:

```json
{
  "mcpServers": {
    "tracesleuth": {
      "command": "ssh",
      "args": ["-T", "ale@192.168.1.23",
        "TRACESLEUTH_DATA=/home/ale/tracesleuth/data TRACESLEUTH_HOST=fedora TRACESLEUTH_EXECUTOR=mock /home/ale/tracesleuth/bin/tracesleuth-mcp"]
    }
  }
}
```

Run `claude` from the repo root and approve the server (or `claude mcp add`). Ask
the agent to, e.g., *"investigate tcp_connect latency on fedora"* and it will call
`list_probe_catalog`, `open_investigation`, `run_probe`, `close_investigation`.

Drop `TRACESLEUTH_EXECUTOR=mock` once real bpftrace is enabled (a NOPASSWD sudo
rule scoped to `/usr/bin/bpftrace`; see the main README).

## Identity comes from the transport, not the client

The server resolves the caller via an `IdentityResolver` (`internal/transport`)
at startup — it does **not** trust an identity string the client sends. Over SSH
it derives the caller from the session (`ssh:<user>`, Teleport user + roles when
present); a client that passes `identity: "someone-else"` is ignored when a
transport identity was resolved. The recorded `agent_identity` in the audit log
is therefore the real, transport-verified caller.

## Teleport: SSH and mTLS, one CA, two resolvers

The plan calls for both transports supported at once, both issued by the same
Teleport CA:

- **SSH (via `tsh`)** — interactive/human use and simple agent setups. Swap
  `"command": "ssh"` for `"command": "tsh"`, `"args": ["ssh", "ale@node", …]`.
  The `SSHResolver` reads the Teleport user/roles from the session.
- **mTLS (via `tbot`)** — programmatic clients wanting a direct connection
  without the SSH proxy. `tbot` writes a TLS identity; a front-end that accepts
  the client cert uses `MTLSResolver`, which reads the identity from the cert's
  CommonName/URI-SAN and roles from the Subject Organization — the encoding
  Teleport uses.

Both are implementations of the same `IdentityResolver` interface, so the daemon
logic, policy input, and audit schema never change between them. Standing up a
live Teleport cluster (auth+proxy on the host, `tsh`/`tbot` on the client) is a
deployment step; the resolvers are built and unit-tested
(`internal/transport/resolver_test.go`).

## Poking the server by hand

`scripts/mcp_smoke.sh` drives a full JSON-RPC session (initialize, tools/list,
catalog, open, allowed+denied probe, close, show, verify) against the mock
backend — useful for debugging without an MCP client.
