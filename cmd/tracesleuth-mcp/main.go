// Command tracesleuth-mcp exposes TraceSleuth's investigation surface to an
// agent over stdio JSON-RPC 2.0 (the Model Context Protocol). It is launched per
// connection — typically over ssh / tsh ssh — resolves the caller from the
// transport, and serves the MCP surface against a local data directory.
//
// Transport: newline-delimited JSON-RPC on stdin/stdout. NOTHING except protocol
// messages may be written to stdout; all diagnostics go to stderr.
//
// Config via environment:
//
//	TRACESLEUTH_DATA      data directory (default ./data)
//	TRACESLEUTH_HOST      host label recorded on investigations (default hostname)
//	TRACESLEUTH_IDENTITY  default caller identity if no transport identity resolves
//	TRACESLEUTH_EXECUTOR  "mock" forces the fake backend; otherwise real bpftrace on Linux
package main

import (
	"log"
	"os"

	"tracesleuth/internal/mcp"
	"tracesleuth/internal/service"
	"tracesleuth/internal/transport"
)

func main() {
	log.SetOutput(os.Stderr)
	log.SetPrefix("tracesleuth-mcp: ")

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

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
