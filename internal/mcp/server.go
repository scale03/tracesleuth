// Package mcp implements TraceSleuth's Model Context Protocol surface:
// newline-delimited JSON-RPC 2.0 over any reader/writer pair — stdio for the
// ssh shim, a Unix-socket connection for the daemon. One Server handles one
// connection, with a fixed identity for that connection's lifetime.
package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"

	"tracesleuth/internal/service"
)

const (
	serverName    = "tracesleuth"
	serverVersion = "0.1.0"
	// defaultProtocol is used when the client doesn't request a version; we echo
	// the client's when present for forward-compatibility.
	defaultProtocol = "2025-06-18"
)

// Server serves the MCP surface for one connection.
type Server struct {
	svc *service.Service
	// identity is the caller, fixed for this connection.
	identity service.Identity
	// identityVerified is true when identity came from a transport (SSH/mTLS/peer
	// credentials) rather than a fallback label — when true, a client-supplied
	// identity argument is ignored so the caller can't spoof who they are.
	identityVerified bool
	host             string
	// w is the response writer, held so a handler can emit progress notifications
	// mid-call. All writes happen on the Serve goroutine.
	w *bufio.Writer
}

// NewServer binds the investigation service to one connection's identity.
func NewServer(svc *service.Service, identity service.Identity, identityVerified bool, host string) *Server {
	return &Server{svc: svc, identity: identity, identityVerified: identityVerified, host: host}
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

// Serve runs the read-dispatch-write loop over newline-delimited JSON-RPC until
// the reader is exhausted (the client disconnects).
func (s *Server) Serve(r io.Reader, w io.Writer) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024) // scripts can be large
	s.w = bufio.NewWriter(w)

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

// ctx is a background context; probe durations are enforced inside the executor.
func ctx() context.Context { return context.Background() }

// fmtErr is a tiny helper for consistent tool text.
func fmtErr(format string, a ...any) string { return fmt.Sprintf(format, a...) }
