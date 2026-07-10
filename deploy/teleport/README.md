# Teleport (demo-grade) for TraceSleuth

Stands up an all-in-one Teleport cluster (auth + proxy + SSH node) so the MCP
server is reached over `tsh ssh` and identity flows from a Teleport certificate.
This is **demo-grade**: self-signed certs (`tsh --insecure`), second factor off,
Teleport runs as an unprivileged user (sessions run as that user), single node.
For production: real TLS, 2FA/SSO, a dedicated system user, and `tbot` instead of
a long-lived identity file.

## On the Linux host

```sh
# install (non-root)
curl -fsSL -o tp.tar.gz https://cdn.teleport.dev/teleport-v18.10.0-linux-amd64-bin.tar.gz
tar xzf tp.tar.gz && mv teleport teleport-dist
mkdir -p ~/teleport/data

# start (background, survives logout)
nohup ./teleport-dist/teleport start -c ~/teleport/teleport.yaml >~/teleport/stdout.log 2>&1 &

T="./teleport-dist/tctl -c ~/teleport/teleport.yaml"
$T status                                   # cluster up?
$T create -f ~/teleport/role.yaml
$T create -f ~/teleport/user.yaml
$T auth sign --user=ale --format=file --out=~/ale.identity --ttl=12h
```

`tctl` needs `-c <config>` so it uses the same `data_dir` as the running auth
service (otherwise it looks in `/var/lib/teleport`).

## On the Mac (client)

```sh
# tsh ships inside a .app bundle; copy the binary out and ad-hoc re-sign it
cp teleport/tsh.app/Contents/MacOS/tsh ~/.tracesleuth/bin/tsh
codesign --force --sign - ~/.tracesleuth/bin/tsh

scp ale@HOST:~/ale.identity ~/.tracesleuth/ale.identity

# one-off command via the identity file (no tsh login / no 2FA needed)
tsh -i ~/.tracesleuth/ale.identity --proxy=HOST:3080 --insecure --user=ale \
    ssh ale@fedora 'echo $SSH_TELEPORT_USER'
```

The MCP client (`.mcp.json`) uses exactly this `tsh ... ssh ale@fedora <remote
cmd>` form, so identity reaches the daemon as `ssh:ale` from the Teleport cert.

## Lifecycle notes

- **Identity TTL:** the signed identity file lasts `--ttl` (12h here). Re-run
  `tctl auth sign` to refresh, or switch to `tbot` for auto-renewing credentials
  (this is also the mTLS path — `MTLSResolver`).
- **Not restart-safe:** started via `nohup`, so a host reboot stops it. Wrap in a
  systemd (user) unit for persistence.
- **Stop:** `pkill -x teleport`.
