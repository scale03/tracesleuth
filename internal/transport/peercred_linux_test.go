//go:build linux

package transport

import (
	"net"
	"os/user"
	"path/filepath"
	"testing"
)

// A connection from this process resolves to this process's own user: the uid is
// read from the kernel, then mapped to a username.
func TestPeerIdentityIsConnectingUser(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "t.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		c, err := net.Dial("unix", sock)
		if err == nil {
			// Hold the connection open until the test reads credentials.
			t.Cleanup(func() { c.Close() })
		}
	}()

	c, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	id, err := PeerIdentity(c.(*net.UnixConn))
	if err != nil {
		t.Fatalf("PeerIdentity: %v", err)
	}
	me, _ := user.Current()
	if id.Name != me.Username {
		t.Fatalf("want identity %q, got %q", me.Username, id.Name)
	}
}
