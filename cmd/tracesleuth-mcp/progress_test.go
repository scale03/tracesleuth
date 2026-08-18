package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"tracesleuth/internal/catalog"
	"tracesleuth/internal/event"
	"tracesleuth/internal/exec"
	"tracesleuth/internal/service"
)

// serverToBuffer builds a Server whose notifications are captured in buf instead
// of being written to a real stdout.
func serverToBuffer(t *testing.T, buf *bytes.Buffer) *Server {
	t.Helper()
	svc, err := service.New(service.Config{
		DataDir:    t.TempDir(),
		Host:       "test-host",
		Executor:   exec.NewMock(),
		Catalog:    catalog.Default(),
		CaptureEnv: func() event.Environment { return event.Environment{Arch: "amd64"} },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { svc.Close() })
	return &Server{svc: svc, identity: service.Identity{Name: "bot"}, host: "test-host", w: bufio.NewWriter(buf)}
}

// runProbe drives open + run_probe through the dispatch layer, passing a
// tools/call params blob so the _meta.progressToken is honored.
func runProbe(t *testing.T, s *Server, meta string) {
	t.Helper()
	openArgs, _ := json.Marshal(map[string]any{"hypothesis": "h"})
	openParams, _ := json.Marshal(callParams{Name: "open_investigation", Arguments: openArgs})
	openRes := s.callTool(openParams)
	openText := openRes["content"].([]map[string]any)[0]["text"].(string)
	inv := strings.Fields(openText)[2]

	args := map[string]any{
		"investigation_id": inv,
		"script":           "kprobe:tcp_connect { @=count(); }",
		"probe_types":      []string{"kprobe"},
		"attach_points":    []string{"tcp_connect"},
		"duration_s":       1,
	}
	argsJSON, _ := json.Marshal(args)
	// Assemble tools/call params by hand so we can inject _meta.
	raw := `{"name":"run_probe","arguments":` + string(argsJSON) + meta + `}`
	s.callTool(json.RawMessage(raw))
}

// progressLines returns the notifications/progress messages captured in buf.
func progressLines(t *testing.T, buf *bytes.Buffer) []string {
	t.Helper()
	var msgs []string
	for _, ln := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if ln == "" {
			continue
		}
		var m struct {
			Method string `json:"method"`
			Params struct {
				Message string `json:"message"`
			} `json:"params"`
		}
		if err := json.Unmarshal([]byte(ln), &m); err != nil {
			t.Fatalf("bad notification line %q: %v", ln, err)
		}
		if m.Method == "notifications/progress" {
			msgs = append(msgs, m.Params.Message)
		}
	}
	return msgs
}

// With a progress token, a run emits an ordered sequence of stage notifications.
func TestRunProbeStreamsProgress(t *testing.T) {
	var buf bytes.Buffer
	s := serverToBuffer(t, &buf)
	runProbe(t, s, `,"_meta":{"progressToken":"tok-1"}`)

	msgs := progressLines(t, &buf)
	joined := strings.Join(msgs, "|")
	for _, stage := range []string{"validating", "policy", "attaching", "capturing", "flushing", "done"} {
		if !strings.Contains(joined, stage) {
			t.Errorf("missing %q stage in progress: %v", stage, msgs)
		}
	}
	// Order must be monotonic through the pipeline.
	if idx(joined, "validating") > idx(joined, "capturing") || idx(joined, "capturing") > idx(joined, "done") {
		t.Fatalf("progress stages out of order: %v", msgs)
	}
}

// The progress token is echoed back on every notification so the client can
// correlate them with its request.
func TestProgressCarriesToken(t *testing.T) {
	var buf bytes.Buffer
	s := serverToBuffer(t, &buf)
	runProbe(t, s, `,"_meta":{"progressToken":"tok-42"}`)
	if !strings.Contains(buf.String(), `"progressToken":"tok-42"`) {
		t.Fatalf("progress token not echoed:\n%s", buf.String())
	}
}

// Without a token there is nothing to correlate against, so no progress is sent.
func TestNoTokenNoProgress(t *testing.T) {
	var buf bytes.Buffer
	s := serverToBuffer(t, &buf)
	runProbe(t, s, "")
	if msgs := progressLines(t, &buf); len(msgs) != 0 {
		t.Fatalf("expected no progress without a token, got %v", msgs)
	}
}

func idx(hay, needle string) int { return strings.Index(hay, needle) }
