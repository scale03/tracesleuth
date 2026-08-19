# Deploying TraceSleuth

Two shapes are planned: a standalone host (below) and Kubernetes (later). This
covers the standalone host — `tracesleuthd` as a systemd service, reached by an
agent over ssh.

## What runs where

```
agent ──ssh──▶ tracesleuth-mcp -connect …   (ephemeral, runs as the ssh user)
                        │ Unix socket
                        ▼
                 tracesleuthd (systemd, user: tracesleuth)
                 ├─ /var/lib/tracesleuth   data: JSONL audit log + SQLite index
                 ├─ /run/tracesleuth/…sock MCP surface
                 ├─ sudo → /usr/bin/bpftrace   (scoped, the only privilege)
                 └─ 127.0.0.1:9464   /healthz, /metrics
```

`tracesleuthd` is long-lived and owns the data. The agent never runs it directly:
it runs the `tracesleuth-mcp` relay, which forwards stdio to the socket. Identity
is the relay process's kernel-attested uid (`SO_PEERCRED`) — i.e. the user the
ssh session authenticated as — so a client can't claim to be someone else.

## Requirements

- Linux with `bpftrace` installed, and BTF (`/sys/kernel/btf/vmlinux`) or matching
  kernel headers.
- A Go toolchain to build (or drop prebuilt binaries in `bin/`).

## Install

From a checkout on the host:

```
sudo deploy/install.sh
```

It builds `tracesleuthd` and `tracesleuth-mcp`, creates the `tracesleuth` system
user, installs the systemd unit and the scoped sudoers rule, and starts the
service. Re-run it to update in place. Verify:

```
systemctl status tracesleuthd
curl -s http://127.0.0.1:9464/healthz      # -> ok
curl -s http://127.0.0.1:9464/metrics      # Prometheus exposition
```

## Connecting an agent

Add the human/agent's login to the `tracesleuth` group so it can reach the socket:

```
sudo usermod -aG tracesleuth alice
```

Point the MCP client at the relay over ssh. For a Claude Code `.mcp.json`:

```json
{
  "mcpServers": {
    "tracesleuth": {
      "command": "ssh",
      "args": ["alice@host", "tracesleuth-mcp", "-connect", "/run/tracesleuth/tracesleuth.sock"]
    }
  }
}
```

The investigation is attributed to `alice` (the ssh user), recorded in the audit
log, and enforced by policy regardless of what the client sends.

## Configuration

Defaults work with no config: the daemon uses its built-in policy and catalog and
the machine hostname. To override, edit `/etc/tracesleuth/tracesleuth.env` (see
`tracesleuth.env.example`) and `systemctl restart tracesleuthd`. Putting the
policy and catalog on disk (`TRACESLEUTH_POLICY`, `TRACESLEUTH_CATALOG`) makes
them reviewable and changeable without a rebuild.

## Metrics

`/metrics` binds to `127.0.0.1:9464` by default. Scrape it locally, or bind it
wider (`TRACESLEUTH_HTTP`) only behind your own auth/firewall. It exposes
investigations opened, probe decisions by outcome, a probe-duration histogram,
and a gauge of probes currently attached.

## Uninstall

```
sudo systemctl disable --now tracesleuthd
sudo rm /etc/systemd/system/tracesleuthd.service /etc/sudoers.d/tracesleuth
sudo rm -rf /usr/local/bin/tracesleuthd /usr/local/bin/tracesleuth-mcp /etc/tracesleuth
# data is left at /var/lib/tracesleuth; remove it deliberately.
```
