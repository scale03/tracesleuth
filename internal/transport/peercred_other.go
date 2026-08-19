//go:build !linux

package transport

import (
	"fmt"
	"net"

	"tracesleuth/internal/service"
)

// PeerIdentity is Linux-only: SO_PEERCRED has no portable equivalent. The daemon
// runs on Linux (bpftrace needs it); this stub keeps non-Linux builds compiling.
func PeerIdentity(_ *net.UnixConn) (service.Identity, error) {
	return service.Identity{}, fmt.Errorf("peer credentials not supported on this platform")
}

// PeerCredsSupported reports whether this platform can read peer credentials.
func PeerCredsSupported() bool { return false }
