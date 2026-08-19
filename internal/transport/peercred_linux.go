//go:build linux

package transport

import (
	"net"
	"os/user"
	"strconv"
	"syscall"

	"tracesleuth/internal/service"
)

// PeerIdentity derives the caller from a Unix-socket peer's kernel credentials
// (SO_PEERCRED). The uid is attested by the kernel, not supplied by the client,
// so a caller connecting through the ssh shim is exactly the user their ssh
// session authenticated as. This is the identity boundary for the standalone
// daemon: SSH authenticates, the shim runs as that user, the kernel vouches for
// the uid here.
func PeerIdentity(conn *net.UnixConn) (service.Identity, error) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return service.Identity{}, err
	}
	var cred *syscall.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	}); err != nil {
		return service.Identity{}, err
	}
	if credErr != nil {
		return service.Identity{}, credErr
	}

	name := "uid:" + strconv.FormatUint(uint64(cred.Uid), 10)
	if u, err := user.LookupId(strconv.FormatUint(uint64(cred.Uid), 10)); err == nil && u.Username != "" {
		name = u.Username
	}
	return service.Identity{Name: name}, nil
}

// PeerCredsSupported reports whether this platform can read peer credentials.
func PeerCredsSupported() bool { return true }
