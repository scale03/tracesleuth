// Command tracesleuth-mcp exposes TraceSleuth's investigation surface to an
// agent over stdio JSON-RPC 2.0 (the Model Context Protocol). It is launched per
// connection — typically over ssh / tsh ssh — and runs in one of two modes:
//
//   - relay (-connect / TRACESLEUTH_SOCKET set): pipe stdio to the tracesleuthd
//     Unix socket. The daemon owns the data and derives identity from this
//     process's kernel credentials. This is the standalone deployment path.
//   - direct (default): resolve identity from the transport and serve the MCP
//     surface in-process against a local data directory. Used for simple setups
//     and development, with no daemon.
//
// Transport: newline-delimited JSON-RPC on stdin/stdout. NOTHING except protocol
// messages may be written to stdout; all diagnostics go to stderr.
//
// Config via environment:
//
//	TRACESLEUTH_SOCKET    daemon socket to relay to; if set, relay mode
//	TRACESLEUTH_DATA      data directory (direct mode; default ./data)
//	TRACESLEUTH_HOST      host label recorded on investigations (default hostname)
//	TRACESLEUTH_IDENTITY  default caller identity if no transport identity resolves
//	TRACESLEUTH_EXECUTOR  "mock" forces the fake backend; otherwise real bpftrace on Linux
package main

import (
	"flag"
	"io"
	"log"
	"net"
	"os"

	"tracesleuth/internal/mcp"
	"tracesleuth/internal/service"
	"tracesleuth/internal/transport"
)

func main() {
	log.SetOutput(os.Stderr)
	log.SetPrefix("tracesleuth-mcp: ")

	connect := flag.String("connect", os.Getenv("TRACESLEUTH_SOCKET"), "tracesleuthd Unix socket to relay to; empty serves in-process")
	flag.Parse()
	if *connect != "" {
		if err := relay(*connect); err != nil {
			log.Fatalf("relay: %v", err)
		}
		return
	}

	data := env("TRACESLEUTH_DATA", "./data")
	host := env("TRACESLEUTH_HOST", "")
	if host == "" {
		host, _ = os.Hostname()
	}

	// Catalog + policy load from TRACESLEUTH_CATALOG / TRACESLEUTH_POLICY when set,
	// otherwise from the built-ins compiled into the binary. tracectl uses the same
	// loader, so every entry point enforces identically.
	cat, engine, err := service.PolicyFromEnv()
	if err != nil {
		log.Fatalf("policy: %v", err)
	}
	log.Printf("policy engine ready (bundle %s)", cat.BundleVersion)

	svc, err := service.New(service.Config{DataDir: data, Host: host, Catalog: cat, Policy: engine})
	if err != nil {
		log.Fatalf("init: %v", err)
	}
	defer svc.Close()

	// Identity comes from the transport, not a hardcoded string. Launched over ssh,
	// the SSH resolver derives the caller from the session; only if none resolves
	// (local/mock dev) do we fall back to a configured label.
	identity := service.Identity{Name: env("TRACESLEUTH_IDENTITY", "mcp-agent")}
	identityVerified := false
	if id, err := transport.NewSSHResolver(os.Getenv).Resolve(); err == nil {
		identity, identityVerified = id, true
		log.Printf("identity from ssh transport: %s roles=%v", id.Name, id.Roles)
	} else {
		log.Printf("no transport identity (%v); falling back to %q", err, identity.Name)
	}

	log.Printf("ready — data=%s host=%s", data, host)
	srv := mcp.NewServer(svc, identity, identityVerified, host)
	if err := srv.Serve(os.Stdin, os.Stdout); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

// relay pipes stdin/stdout to the daemon socket. The daemon reads this process's
// kernel credentials for identity, so the relay carries no identity of its own —
// it only forwards bytes. When stdin ends it half-closes the socket to signal
// EOF, then keeps forwarding the daemon's replies until the daemon closes; that
// ordering is what lets the last response drain instead of being cut off.
func relay(socket string) error {
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return err
	}
	defer conn.Close()
	uc := conn.(*net.UnixConn)

	go func() {
		io.Copy(uc, os.Stdin)
		uc.CloseWrite() // EOF to the daemon; the read half stays open for replies
	}()
	_, err = io.Copy(os.Stdout, uc)
	return err
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
