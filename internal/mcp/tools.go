package mcp

import (
	"encoding/json"
	"fmt"
	"strings"

	"tracesleuth/internal/catalog"
	"tracesleuth/internal/service"
)

// toolSpecs returns the MCP tool definitions (name, description, JSON Schema).
// The schemas are the contract the agent writes against, so descriptions carry
// the constraints (aggregation on high-frequency points, coarse-then-narrow)
// that policy enforces — an agent that reads them gets a near-zero denial rate.
func toolSpecs() []map[string]any {
	obj := func(props map[string]any, required ...string) map[string]any {
		m := map[string]any{"type": "object", "properties": props}
		if len(required) > 0 {
			m["required"] = required
		}
		return m
	}
	str := map[string]any{"type": "string"}
	strArr := map[string]any{"type": "array", "items": map[string]any{"type": "string"}}

	return []map[string]any{
		{
			"name":        "list_probe_catalog",
			"description": "List allowed probe types and attach points, grouped by category, with which are high-frequency (require an aggregation like count/sum/hist/@map instead of raw per-event output) and the duration limits. Call this before writing a script.",
			"inputSchema": obj(map[string]any{}),
		},
		{
			"name":        "list_kernel_probes",
			"description": "List the probes this host actually exposes (live `bpftrace -l`), narrowed by a probe glob and paged. This is discovery of everything the kernel has — a wider net than list_probe_catalog's curated set. Use a filter to stay focused (\"tracepoint:*\" for all tracepoints, \"kprobe:tcp*\" for TCP kprobes, \"tracepoint:syscalls:*\" for syscalls); the host exposes thousands, so results are capped — page with offset.",
			"inputSchema": obj(map[string]any{
				"filter": merge(str, map[string]any{"description": "bpftrace probe glob, e.g. \"tracepoint:*\" or \"kprobe:tcp*\"; omit for everything"}),
				"offset": map[string]any{"type": "integer", "description": "index of the first result (for paging); default 0"},
				"limit":  map[string]any{"type": "integer", "description": "max results to return; default 100"},
			}),
		},
		{
			"name":        "open_investigation",
			"description": "Open a new investigation and record its hypothesis. Returns the investigation_id to pass to run_probe and close_investigation.",
			"inputSchema": obj(map[string]any{
				"hypothesis": map[string]any{"type": "string", "description": "what you are testing, in one sentence"},
				"identity":   map[string]any{"type": "string", "description": "caller identity label (optional; defaults to the server's configured identity)"},
			}, "hypothesis"),
		},
		{
			"name":        "run_probe",
			"description": "Validate (dry-run + policy), then run one bpftrace probe within an investigation, capturing its output. Returns a status line, the exact script, the policy decision, and a byte-capped output summary (full output is saved to disk). If policy denies it, nothing runs and the response is the actionable reason. Rules: high-frequency attach points require an aggregation; the first probe in an investigation must be short (<=30s), filtered (pid/comm), or aggregated.",
			"inputSchema": obj(map[string]any{
				"investigation_id": str,
				"script":           map[string]any{"type": "string", "description": "the bpftrace program text"},
				"probe_types":      merge(strArr, map[string]any{"description": "e.g. [\"kprobe\",\"kretprobe\"]"}),
				"attach_points":    merge(strArr, map[string]any{"description": "attach points from the catalog, e.g. [\"tcp_connect\"]"}),
				"duration_s":       map[string]any{"type": "integer", "description": "seconds; 0 or omitted uses the catalog default"},
				"filter_pid":       map[string]any{"type": "boolean", "description": "true if the script is scoped by pid"},
				"filter_comm":      map[string]any{"type": "boolean", "description": "true if the script is scoped by comm"},
			}, "investigation_id", "script"),
		},
		{
			"name":        "preview_probe",
			"description": "Dry-run and policy-check a probe and estimate its cost WITHOUT running it or recording anything. Use this to show a human the exact script and the allow/deny decision before committing to a run. Same inputs as run_probe; investigation_id is optional (supply it to reflect that investigation's context, e.g. the first-probe rule).",
			"inputSchema": obj(map[string]any{
				"investigation_id": merge(str, map[string]any{"description": "optional; evaluate against this investigation's context"}),
				"script":           map[string]any{"type": "string", "description": "the bpftrace program text"},
				"probe_types":      merge(strArr, map[string]any{"description": "e.g. [\"kprobe\",\"kretprobe\"]"}),
				"attach_points":    merge(strArr, map[string]any{"description": "attach points from the catalog, e.g. [\"tcp_connect\"]"}),
				"duration_s":       map[string]any{"type": "integer", "description": "seconds; 0 or omitted uses the catalog default"},
				"filter_pid":       map[string]any{"type": "boolean", "description": "true if the script is scoped by pid"},
				"filter_comm":      map[string]any{"type": "boolean", "description": "true if the script is scoped by comm"},
			}, "script"),
		},
		{
			"name":        "close_investigation",
			"description": "Close an investigation with a short recap. Write the conclusion as a couple of sentences a teammate could read cold: what the hypothesis was, what the probes showed, and the answer. Returns the full summary card (hypothesis, environment, each probe's finding, conclusion).",
			"inputSchema": obj(map[string]any{
				"investigation_id": str,
				"conclusion":       merge(str, map[string]any{"description": "the recap: what you found and concluded, in prose"}),
			}, "investigation_id", "conclusion"),
		},
		{
			"name":        "show_investigation",
			"description": "Return an investigation's summary card from the index: hypothesis, the environment it ran on, each probe with its decision and finding, and the conclusion.",
			"inputSchema": obj(map[string]any{"investigation_id": str}, "investigation_id"),
		},
	}
}

func merge(a, b map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// --- dispatch ---------------------------------------------------------------

type callParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
	// Meta carries the optional MCP progress token; when present, run_probe
	// streams notifications/progress against it during the capture.
	Meta struct {
		ProgressToken json.RawMessage `json:"progressToken"`
	} `json:"_meta"`
}

// callTool routes a tools/call to the matching handler and wraps the result in
// the MCP content shape. Tool-level failures set isError=true with a message,
// rather than a JSON-RPC error, so the agent sees them as tool output.
func (s *Server) callTool(params json.RawMessage) map[string]any {
	var p callParams
	if err := json.Unmarshal(params, &p); err != nil {
		return textResult("bad tool call: "+err.Error(), true)
	}
	switch p.Name {
	case "list_probe_catalog":
		return textResult(renderCatalog(s.svc.Catalog()), false)
	case "list_kernel_probes":
		return s.toolListKernelProbes(p.Arguments)
	case "open_investigation":
		return s.toolOpen(p.Arguments)
	case "run_probe":
		return s.toolRunProbe(p.Arguments, s.progressFn(p.Meta.ProgressToken))
	case "preview_probe":
		return s.toolPreview(p.Arguments)
	case "close_investigation":
		return s.toolClose(p.Arguments)
	case "show_investigation":
		return s.toolShow(p.Arguments)
	default:
		return textResult("unknown tool: "+p.Name, true)
	}
}

func (s *Server) toolListKernelProbes(args json.RawMessage) map[string]any {
	var a struct {
		Filter string `json:"filter"`
		Offset int    `json:"offset"`
		Limit  int    `json:"limit"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return textResult("bad arguments: "+err.Error(), true)
	}
	listing, err := s.svc.ListKernelProbes(ctx(), a.Filter, a.Offset, a.Limit)
	if err != nil {
		return textResult("list_kernel_probes failed: "+err.Error(), true)
	}
	return textResult(renderListing(listing), false)
}

// renderListing formats one page of host probe discovery, ending with a paging
// hint when more remain.
func renderListing(l service.ProbeListing) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d probes match %q", l.Total, l.Filter)
	if l.Total == 0 {
		b.WriteString("\n(no probe on this host matches — check the glob, e.g. \"tracepoint:*\")")
		return b.String()
	}
	fmt.Fprintf(&b, " — showing %d–%d\n\n", l.Offset+1, l.Offset+len(l.Probes))
	for _, p := range l.Probes {
		b.WriteString(p)
		b.WriteByte('\n')
	}
	if l.HasMore() {
		fmt.Fprintf(&b, "\n… %d more. Page with offset=%d.", l.Total-(l.Offset+len(l.Probes)), l.Offset+len(l.Probes))
	}
	return b.String()
}

func (s *Server) toolOpen(args json.RawMessage) map[string]any {
	var a struct {
		Hypothesis string `json:"hypothesis"`
		Identity   string `json:"identity"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return textResult("bad arguments: "+err.Error(), true)
	}
	if strings.TrimSpace(a.Hypothesis) == "" {
		return textResult("hypothesis is required", true)
	}
	// A verified transport identity always wins; a client-supplied identity is
	// only honored as a label when no transport identity was resolved.
	identity := s.identity
	if !s.identityVerified && a.Identity != "" {
		identity = service.Identity{Name: a.Identity}
	}
	inv, err := s.svc.Open(identity)
	if err != nil {
		return textResult("open failed: "+err.Error(), true)
	}
	if err := s.svc.Hypothesis(inv, a.Hypothesis); err != nil {
		return textResult("hypothesis failed: "+err.Error(), true)
	}
	return textResult(fmtErr("opened investigation %s on host %s as %s\nhypothesis: %s", inv, s.host, identity.Name, a.Hypothesis), false)
}

// progressFn returns a callback that emits an MCP progress notification per
// stage, or nil when the client sent no progress token (nothing to notify).
func (s *Server) progressFn(token json.RawMessage) func(service.ProbeProgress) {
	if len(token) == 0 || string(token) == "null" {
		return nil
	}
	var n int
	return func(p service.ProbeProgress) {
		n++
		s.notify("notifications/progress", map[string]any{
			"progressToken": token,
			"progress":      n,
			"message":       p.Stage + ": " + p.Message,
		})
	}
}

func (s *Server) toolRunProbe(args json.RawMessage, progress func(service.ProbeProgress)) map[string]any {
	var a struct {
		InvestigationID string   `json:"investigation_id"`
		Script          string   `json:"script"`
		ProbeTypes      []string `json:"probe_types"`
		AttachPoints    []string `json:"attach_points"`
		DurationS       int      `json:"duration_s"`
		FilterPID       bool     `json:"filter_pid"`
		FilterComm      bool     `json:"filter_comm"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return textResult("bad arguments: "+err.Error(), true)
	}
	if a.InvestigationID == "" || strings.TrimSpace(a.Script) == "" {
		return textResult("investigation_id and script are required", true)
	}
	rep, err := s.svc.RunProbe(ctx(), a.InvestigationID, service.ProbeRequest{
		ProbeTypes:   a.ProbeTypes,
		AttachPoints: a.AttachPoints,
		ScriptText:   a.Script,
		DurationS:    a.DurationS,
		FilterPID:    a.FilterPID,
		FilterComm:   a.FilterComm,
	}, progress)
	if err != nil {
		return textResult("run_probe failed: "+err.Error(), true)
	}
	// A denial is a normal, non-error result: the rendered text IS the actionable
	// reason the agent should act on.
	return textResult(rep.Render(), false)
}

func (s *Server) toolPreview(args json.RawMessage) map[string]any {
	var a struct {
		InvestigationID string   `json:"investigation_id"`
		Script          string   `json:"script"`
		ProbeTypes      []string `json:"probe_types"`
		AttachPoints    []string `json:"attach_points"`
		DurationS       int      `json:"duration_s"`
		FilterPID       bool     `json:"filter_pid"`
		FilterComm      bool     `json:"filter_comm"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return textResult("bad arguments: "+err.Error(), true)
	}
	if strings.TrimSpace(a.Script) == "" {
		return textResult("script is required", true)
	}
	rep, err := s.svc.PreviewProbe(ctx(), a.InvestigationID, service.ProbeRequest{
		ProbeTypes:   a.ProbeTypes,
		AttachPoints: a.AttachPoints,
		ScriptText:   a.Script,
		DurationS:    a.DurationS,
		FilterPID:    a.FilterPID,
		FilterComm:   a.FilterComm,
	})
	if err != nil {
		return textResult("preview failed: "+err.Error(), true)
	}
	return textResult(rep.Render(), false)
}

func (s *Server) toolClose(args json.RawMessage) map[string]any {
	var a struct {
		InvestigationID string `json:"investigation_id"`
		Conclusion      string `json:"conclusion"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return textResult("bad arguments: "+err.Error(), true)
	}
	if a.InvestigationID == "" || a.Conclusion == "" {
		return textResult("investigation_id and conclusion are required", true)
	}
	if err := s.svc.Close_(a.InvestigationID, a.Conclusion); err != nil {
		return textResult("close failed: "+err.Error(), true)
	}
	// Closing returns the full recap card, so the investigation ends summarized.
	card, ok, err := s.svc.SummaryCard(a.InvestigationID)
	if err != nil || !ok {
		return textResult("closed "+a.InvestigationID, false)
	}
	return textResult(card, false)
}

func (s *Server) toolShow(args json.RawMessage) map[string]any {
	var a struct {
		InvestigationID string `json:"investigation_id"`
	}
	if err := json.Unmarshal(args, &a); err != nil {
		return textResult("bad arguments: "+err.Error(), true)
	}
	text, ok, err := s.svc.SummaryCard(a.InvestigationID)
	if err != nil {
		return textResult("show failed: "+err.Error(), true)
	}
	if !ok {
		return textResult("investigation not found: "+a.InvestigationID, true)
	}
	return textResult(text, false)
}

// textResult wraps text in the MCP tool-result content shape.
func textResult(text string, isError bool) map[string]any {
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": text}},
		"isError": isError,
	}
}

// renderCatalog formats the catalog for the list_probe_catalog result.
func renderCatalog(c catalog.Catalog) string {
	var b strings.Builder
	b.WriteString("bundle " + c.BundleVersion)
	b.WriteString("\nposture: default-allow + deny-list — full bpftrace capability; policy denies only the points/modalities below")
	b.WriteString("\nlimits: default duration " + itoa(c.DefaultDuration) + "s, max " + itoa(c.MaxDuration) + "s, max concurrent " + itoa(c.MaxConcurrent))
	b.WriteString("\nprobe types: " + strings.Join(c.ProbeTypes, ", ") + " (advertised; other kinds are allowed unless denied)")
	if len(c.DeniedAttachPoints) > 0 || len(c.DeniedProbeTypes) > 0 {
		b.WriteString("\ndenied by policy:")
		if len(c.DeniedAttachPoints) > 0 {
			b.WriteString(" attach=" + strings.Join(c.DeniedAttachPoints, ","))
		}
		if len(c.DeniedProbeTypes) > 0 {
			b.WriteString(" types=" + strings.Join(c.DeniedProbeTypes, ","))
		}
	}
	b.WriteString("\n\nknown attach points (discovery — not an allow-list):\n")
	for _, cat := range []catalog.Category{catalog.Network, catalog.Process, catalog.DiskIO, catalog.Scheduler} {
		aps := c.GroupByCategory()[cat]
		if len(aps) == 0 {
			continue
		}
		b.WriteString("\n[" + string(cat) + "]\n")
		for _, ap := range aps {
			b.WriteString("  " + ap.Name)
			if ap.HighFrequency {
				b.WriteString("  [HIGH-FREQUENCY: requires aggregation count/sum/hist/@map]")
			}
			b.WriteString(" — " + ap.Description + "\n")
		}
	}
	return b.String()
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
