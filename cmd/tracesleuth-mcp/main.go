// Command tracesleuth-mcp is an MCP (Model Context Protocol) server that exposes
// TraceSleuth's investigation surface to an agent over stdio JSON-RPC 2.0. This
// is the intended way to use TraceSleuth: an agent calls list_probe_catalog,
// opens an investigation, runs probes (which return the Phase-8 shaped summary —
// script echoed, decision, and a byte-capped output summary), and closes it,
// while the full audit trail is written to the hash-chained JSONL log.
//
// Transport: newline-delimited JSON-RPC messages on stdin/stdout. NOTHING except
// protocol messages may be written to stdout; all diagnostics go to stderr.
//
// Config via environment:
//
//	TRACESLEUTH_DATA      data directory (default ./data)
//	TRACESLEUTH_HOST      host label recorded on investigations (default hostname)
//	TRACESLEUTH_IDENTITY  default caller identity if a tool omits it (default "mcp-agent")
//	TRACESLEUTH_EXECUTOR  "mock" forces the fake backend; otherwise real bpftrace on Linux
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"tracesleuth/internal/service"
	"tracesleuth/internal/transport"
)

const (
	serverName    = "tracesleuth"
	serverVersion = "0.1.0"
	// Fallback protocol version if the client doesn't specify one. We echo the
	// client's requested version when present for forward-compatibility.
	defaultProtocol = "2025-06-18"
)

func main() {
	log.SetOutput(os.Stderr)
	log.SetPrefix("tracesleuth-mcp: ")

	data := env("TRACESLEUTH_DATA", "./data")
	host := env("TRACESLEUTH_HOST", "")
	if host == "" {
		host, _ = os.Hostname()
	}

	// Catalog + policy are managed WITHOUT recompiling: TRACESLEUTH_CATALOG points
	// at a JSON catalog (caps, high-frequency set, deny-lists) and TRACESLEUTH_POLICY
	// at a Rego file. Both fall back to the built-ins compiled into the binary. The
	// same loader backs tracectl, so every entry point enforces identically.
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

	// Identity comes from the transport, not a hardcoded string. The MCP server
	// is launched over ssh / tsh ssh, so the SSH resolver derives the caller from
	// the session; an mTLS front-end would supply an MTLSResolver instead. Only
	// if no transport identity is available (e.g. local/mock dev) do we fall back
	// to a configured label.
	identity := service.Identity{Name: env("TRACESLEUTH_IDENTITY", "mcp-agent")}
	identityVerified := false
	if id, err := transport.NewSSHResolver(os.Getenv).Resolve(); err == nil {
		identity, identityVerified = id, true
		log.Printf("identity from ssh transport: %s roles=%v", id.Name, id.Roles)
	} else {
		log.Printf("no transport identity (%v); falling back to %q", err, identity.Name)
	}

	srv := &Server{
		svc:              svc,
		identity:         identity,
		identityVerified: identityVerified,
		host:             host,
	}
	log.Printf("ready — data=%s host=%s", data, host)
	if err := srv.Serve(os.Stdin, os.Stdout); err != nil {
		log.Fatalf("serve: %v", err)
	}
}

// Server holds the wiring; one long-lived instance handles all requests.
type Server struct {
	svc *service.Service
	// identity is the caller, resolved once from the transport at startup.
	identity service.Identity
	// identityVerified is true when identity came from a transport resolver
	// (SSH/mTLS) rather than the fallback label — when true, a client-supplied
	// identity argument is ignored so the caller can't spoof who they are.
	identityVerified bool
	host             string
	// w is the response writer, held so a handler can emit progress
	// notifications mid-call. All writes happen on the Serve goroutine.
	w *bufio.Writer
}

// --- JSON-RPC envelope ------------------------------------------------------

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"` // absent => notification
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Serve runs the read-dispatch-write loop over newline-delimited JSON-RPC.
func (s *Server) Serve(in *os.File, out *os.File) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024) // scripts can be large
	s.w = bufio.NewWriter(out)

	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var req rpcRequest
		if err := json.Unmarshal(line, &req); err != nil {
			log.Printf("bad message: %v", err)
			continue
		}
		resp, isNotification := s.handle(&req)
		if isNotification {
			continue // notifications get no reply
		}
		b, _ := json.Marshal(resp)
		s.w.Write(b)
		s.w.WriteByte('\n')
		if err := s.w.Flush(); err != nil {
			return err
		}
	}
	return sc.Err()
}

// notify writes a JSON-RPC notification (no id, no reply expected) to the client.
// It runs on the Serve goroutine, so it shares the writer without locking.
func (s *Server) notify(method string, params any) {
	if s.w == nil {
		return
	}
	msg, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "method": method, "params": params})
	if err != nil {
		return
	}
	s.w.Write(msg)
	s.w.WriteByte('\n')
	s.w.Flush()
}

func (s *Server) handle(req *rpcRequest) (rpcResponse, bool) {
	resp := rpcResponse{JSONRPC: "2.0", ID: req.ID}
	switch req.Method {
	case "initialize":
		resp.Result = s.initialize(req.Params)
	case "notifications/initialized", "notifications/cancelled":
		return resp, true // notification, no reply
	case "ping":
		resp.Result = map[string]any{}
	case "tools/list":
		resp.Result = map[string]any{"tools": toolSpecs()}
	case "tools/call":
		resp.Result = s.callTool(req.Params)
	default:
		if req.ID == nil {
			return resp, true // unknown notification: ignore
		}
		resp.Error = &rpcError{Code: -32601, Message: "method not found: " + req.Method}
	}
	return resp, false
}

func (s *Server) initialize(params json.RawMessage) map[string]any {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(params, &p)
	proto := p.ProtocolVersion
	if proto == "" {
		proto = defaultProtocol
	}
	return map[string]any{
		"protocolVersion": proto,
		"capabilities":    map[string]any{"tools": map[string]any{}},
		"serverInfo":      map[string]any{"name": serverName, "version": serverVersion},
		"instructions": "TraceSleuth: run auditable bpftrace investigations. " +
			"Call list_probe_catalog first to see allowed probes and which attach points require an aggregation. " +
			"Then open_investigation, run_probe (repeat), and close_investigation. Use preview_probe to check a script's " +
			"decision and cost before running it. Every step is written to a tamper-evident audit log.",
	}
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// ctx is a background context; probe durations are enforced inside the executor.
func ctx() context.Context { return context.Background() }

// fmtErr is a tiny helper for consistent tool error text.
func fmtErr(format string, a ...any) string { return fmt.Sprintf(format, a...) }
