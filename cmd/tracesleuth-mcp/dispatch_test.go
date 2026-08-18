package main

import (
	"encoding/json"
	"strings"
	"testing"

	"tracesleuth/internal/catalog"
	"tracesleuth/internal/exec"
	"tracesleuth/internal/service"
)

func newServer(t *testing.T, identity service.Identity, verified bool) *Server {
	t.Helper()
	svc, err := service.New(service.Config{
		DataDir:  t.TempDir(),
		Host:     "test-host",
		Executor: exec.NewMock(),
		Catalog:  catalog.Default(),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { svc.Close() })
	return &Server{svc: svc, identity: identity, identityVerified: verified, host: "test-host"}
}

// call invokes a tool through the dispatch layer and returns its text plus the
// isError flag.
func call(t *testing.T, s *Server, name string, args map[string]any) (string, bool) {
	t.Helper()
	argsJSON, _ := json.Marshal(args)
	params, _ := json.Marshal(callParams{Name: name, Arguments: argsJSON})
	res := s.callTool(params)
	content, _ := res["content"].([]map[string]any)
	if len(content) == 0 {
		t.Fatalf("tool %s returned no content: %v", name, res)
	}
	isErr, _ := res["isError"].(bool)
	return content[0]["text"].(string), isErr
}

func TestToolsListAdvertisesSurface(t *testing.T) {
	specs := toolSpecs()
	got := map[string]bool{}
	for _, spec := range specs {
		got[spec["name"].(string)] = true
	}
	for _, want := range []string{"list_probe_catalog", "open_investigation", "run_probe", "close_investigation", "show_investigation"} {
		if !got[want] {
			t.Errorf("tools/list is missing %q", want)
		}
	}
}

func TestInitializeEchoesProtocol(t *testing.T) {
	s := newServer(t, service.Identity{Name: "mcp-agent"}, false)
	got := s.initialize(json.RawMessage(`{"protocolVersion":"2024-11-05"}`))
	if got["protocolVersion"] != "2024-11-05" {
		t.Fatalf("client protocol version not echoed: %v", got["protocolVersion"])
	}
	got = s.initialize(json.RawMessage(`{}`))
	if got["protocolVersion"] != defaultProtocol {
		t.Fatalf("missing version should fall back to default, got %v", got["protocolVersion"])
	}
}

func TestUnknownMethodIsJSONRPCError(t *testing.T) {
	s := newServer(t, service.Identity{Name: "mcp-agent"}, false)
	resp, isNotification := s.handle(&rpcRequest{JSONRPC: "2.0", ID: json.RawMessage(`1`), Method: "nope"})
	if isNotification {
		t.Fatal("a request with an id is not a notification")
	}
	if resp.Error == nil || resp.Error.Code != -32601 {
		t.Fatalf("want -32601 method-not-found, got %+v", resp.Error)
	}
}

// A method that isn't understood and carries no id is a notification: ignored,
// no reply.
func TestUnknownNotificationIgnored(t *testing.T) {
	s := newServer(t, service.Identity{Name: "mcp-agent"}, false)
	_, isNotification := s.handle(&rpcRequest{JSONRPC: "2.0", Method: "notifications/something"})
	if !isNotification {
		t.Fatal("id-less unknown method should be treated as a notification")
	}
}

func TestUnknownToolIsToolError(t *testing.T) {
	s := newServer(t, service.Identity{Name: "mcp-agent"}, false)
	text, isErr := call(t, s, "no_such_tool", nil)
	if !isErr || !strings.Contains(text, "unknown tool") {
		t.Fatalf("want tool error, got err=%v text=%q", isErr, text)
	}
}

// The full agent-facing flow: open, run an allowed probe, close, and read it
// back — driven entirely through the dispatch layer.
func TestOpenRunCloseShow(t *testing.T) {
	s := newServer(t, service.Identity{Name: "ci-bot"}, false)

	openText, isErr := call(t, s, "open_investigation", map[string]any{"hypothesis": "tcp_connect latency"})
	if isErr {
		t.Fatalf("open failed: %s", openText)
	}
	inv := investigationID(t, openText)

	runText, isErr := call(t, s, "run_probe", map[string]any{
		"investigation_id": inv,
		"script":           "kprobe:tcp_connect { @=count(); }",
		"probe_types":      []string{"kprobe"},
		"attach_points":    []string{"tcp_connect"},
		"duration_s":       20,
		"filter_pid":       true,
	})
	if isErr {
		t.Fatalf("run_probe errored: %s", runText)
	}
	if !strings.Contains(runText, "allow") {
		t.Fatalf("expected an allow decision in the report:\n%s", runText)
	}

	if _, isErr := call(t, s, "close_investigation", map[string]any{"investigation_id": inv, "conclusion": "confirmed"}); isErr {
		t.Fatal("close failed")
	}
	showText, isErr := call(t, s, "show_investigation", map[string]any{"investigation_id": inv})
	if isErr || !strings.Contains(showText, inv) {
		t.Fatalf("show did not reconstruct %s:\n%s", inv, showText)
	}
}

// The spoof-rejection path: when a transport resolved the identity
// (identityVerified), a client-supplied identity argument is ignored so a caller
// cannot claim to be someone else.
func TestVerifiedIdentityIgnoresClientClaim(t *testing.T) {
	s := newServer(t, service.Identity{Name: "alice@ssh"}, true)
	text, isErr := call(t, s, "open_investigation", map[string]any{
		"hypothesis": "h",
		"identity":   "root@spoofed",
	})
	if isErr {
		t.Fatalf("open failed: %s", text)
	}
	if strings.Contains(text, "root@spoofed") {
		t.Fatalf("client-supplied identity was honored despite a verified transport:\n%s", text)
	}
	if !strings.Contains(text, "alice@ssh") {
		t.Fatalf("verified transport identity not used:\n%s", text)
	}
}

// Without a transport identity, the client-supplied label is honored — the
// standalone/dev fallback.
func TestUnverifiedIdentityHonorsClientClaim(t *testing.T) {
	s := newServer(t, service.Identity{Name: "mcp-agent"}, false)
	text, _ := call(t, s, "open_investigation", map[string]any{
		"hypothesis": "h",
		"identity":   "named-caller",
	})
	if !strings.Contains(text, "named-caller") {
		t.Fatalf("fallback should honor the client label:\n%s", text)
	}
}

// investigationID pulls the id out of "opened investigation <id> on host ...".
func investigationID(t *testing.T, openText string) string {
	t.Helper()
	fields := strings.Fields(openText)
	if len(fields) < 3 || fields[0] != "opened" {
		t.Fatalf("unexpected open response: %q", openText)
	}
	return fields[2]
}
