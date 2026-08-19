package mcp

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// callToolText drives one tools/call through dispatch and returns its text.
func callToolText(t *testing.T, s *Server, name string, args map[string]any) string {
	t.Helper()
	argsJSON, _ := json.Marshal(args)
	params, _ := json.Marshal(callParams{Name: name, Arguments: argsJSON})
	res := s.callTool(params)
	content, _ := res["content"].([]map[string]any)
	if len(content) == 0 {
		t.Fatalf("%s returned no content: %v", name, res)
	}
	return content[0]["text"].(string)
}

func TestListKernelProbesTool(t *testing.T) {
	var buf bytes.Buffer
	s := serverToBuffer(t, &buf) // mock executor: 10 probes

	// A narrow page shows a paging hint.
	text := callToolText(t, s, "list_kernel_probes", map[string]any{"filter": "*", "limit": 4})
	if !strings.Contains(text, "10 probes match") {
		t.Errorf("missing total count:\n%s", text)
	}
	if !strings.Contains(text, "offset=4") {
		t.Errorf("missing paging hint:\n%s", text)
	}

	// A filter narrows to tracepoints only.
	tps := callToolText(t, s, "list_kernel_probes", map[string]any{"filter": "tracepoint:*"})
	if strings.Contains(tps, "kprobe:") {
		t.Errorf("tracepoint filter leaked kprobes:\n%s", tps)
	}

	// A glob that matches nothing explains itself rather than erroring.
	none := callToolText(t, s, "list_kernel_probes", map[string]any{"filter": "uprobe:nope*"})
	if !strings.Contains(none, "0 probes match") {
		t.Errorf("empty match not reported:\n%s", none)
	}
}
