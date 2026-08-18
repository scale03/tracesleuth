#!/usr/bin/env bash
# Install TraceSleuth as a standalone systemd service on this host.
#
# Run as root from a checkout:  sudo deploy/install.sh
#
# It creates a dedicated tracesleuth user, installs the daemon and the MCP relay,
# wires the systemd unit and the scoped sudoers rule, and starts the service.
# Re-running is safe: it updates the binaries and unit in place.
set -euo pipefail

PREFIX="${PREFIX:-/usr/local/bin}"
ETC="/etc/tracesleuth"
UNIT="/etc/systemd/system/tracesleuthd.service"
SUDOERS="/etc/sudoers.d/tracesleuth"
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

die() { echo "error: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "run as root (sudo deploy/install.sh)"
command -v bpftrace >/dev/null || echo "warning: bpftrace not found in PATH; install it before running real probes"

echo "==> building binaries"
command -v go >/dev/null || die "go toolchain not found; install Go or drop prebuilt binaries in $REPO/bin"
( cd "$REPO" && go build -o bin/tracesleuthd ./cmd/tracesleuthd && go build -o bin/tracesleuth-mcp ./cmd/tracesleuth-mcp )

echo "==> creating tracesleuth system user"
if ! getent group tracesleuth >/dev/null; then groupadd --system tracesleuth; fi
if ! id tracesleuth >/dev/null 2>&1; then
  useradd --system --gid tracesleuth --home-dir /var/lib/tracesleuth \
          --shell /usr/sbin/nologin --comment "TraceSleuth daemon" tracesleuth
fi

echo "==> installing binaries to $PREFIX"
install -m 0755 "$REPO/bin/tracesleuthd" "$PREFIX/tracesleuthd"
install -m 0755 "$REPO/bin/tracesleuth-mcp" "$PREFIX/tracesleuth-mcp"

echo "==> installing config to $ETC"
install -d -m 0755 "$ETC"
[ -f "$ETC/tracesleuth.env" ] || install -m 0644 "$REPO/deploy/tracesleuth.env.example" "$ETC/tracesleuth.env"

echo "==> installing scoped sudoers rule"
install -m 0440 "$REPO/deploy/sudoers/tracesleuth" "$SUDOERS"
visudo -c -f "$SUDOERS" >/dev/null || die "sudoers validation failed; removed nothing, fix $SUDOERS"

echo "==> installing systemd unit"
install -m 0644 "$REPO/deploy/systemd/tracesleuthd.service" "$UNIT"
systemctl daemon-reload
systemctl enable --now tracesleuthd

echo
echo "tracesleuthd is running. Check it with:"
echo "    systemctl status tracesleuthd"
echo "    curl -s http://127.0.0.1:9464/healthz"
echo
echo "To let a user drive investigations over ssh, add them to the tracesleuth group:"
echo "    usermod -aG tracesleuth <username>"
echo "and point their MCP client at the relay (see deploy/README.md)."
