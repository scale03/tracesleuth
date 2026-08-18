package service

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"tracesleuth/internal/event"
	"tracesleuth/internal/output"
	"tracesleuth/internal/store"
)

// SummaryCard renders an investigation as a markdown card: hypothesis, the
// environment it ran on, each probe with its decision and actual finding, and
// the conclusion. show_investigation and close_investigation both return it, so
// closing an investigation ends with the whole thing summarized in one place.
// ok is false if the id is unknown.
func (s *Service) SummaryCard(invID string) (string, bool, error) {
	iv, ok, err := s.store.Get(invID)
	if err != nil || !ok {
		return "", ok, err
	}
	var b strings.Builder
	status := iv.Status
	fmt.Fprintf(&b, "## Investigation %s — %s\n\n", iv.ID, status)
	fmt.Fprintf(&b, "**host** %s", iv.Host)
	if env := renderEnv(iv.Environment); env != "" {
		fmt.Fprintf(&b, " · %s", env)
	}
	fmt.Fprintf(&b, "  \n**identity** %s\n\n", iv.AgentIdentity)
	if iv.Hypothesis != "" {
		fmt.Fprintf(&b, "**Hypothesis** — %s\n\n", iv.Hypothesis)
	}

	fmt.Fprintf(&b, "### Probes (%d)\n", len(iv.Probes))
	for _, p := range iv.Probes {
		b.WriteByte('\n')
		fmt.Fprintf(&b, "**%s** · %s", p.ID, p.PolicyDecision)
		if ap := trimJSONArray(p.AttachPoints); ap != "" {
			fmt.Fprintf(&b, " · %s", ap)
		}
		if p.ExitCode.Valid {
			fmt.Fprintf(&b, " · exit %d", p.ExitCode.Int64)
		}
		if p.DurationS.Valid {
			fmt.Fprintf(&b, " · %ds", p.DurationS.Int64)
		}
		b.WriteByte('\n')
		b.WriteString("```bpftrace\n" + strings.TrimRight(p.ScriptText, "\n") + "\n```\n")
		if finding := s.probeFinding(p); finding != "" {
			fmt.Fprintf(&b, "finding:\n```\n%s\n```\n", finding)
		}
	}

	if iv.Conclusion != "" {
		fmt.Fprintf(&b, "\n### Conclusion\n%s\n", iv.Conclusion)
	}
	return b.String(), true, nil
}

// probeFinding derives a one-glance finding for a probe from its captured
// output: the top of the aggregation chart when the script aggregated, or the
// first lines of a raw stream otherwise. A denied probe never ran.
func (s *Service) probeFinding(p store.Probe) string {
	if p.PolicyDecision == "deny" {
		return "denied by policy — did not run"
	}
	if p.OutputPath == "" {
		return ""
	}
	raw, err := os.ReadFile(filepath.Join(s.cfg.DataDir, p.OutputPath))
	if err != nil {
		return ""
	}
	sum := output.Summarize(raw)
	if chart := sum.Chart(); chart != "" {
		return firstNLines(chart, 8)
	}
	return firstNLines(strings.TrimSpace(string(raw)), 4)
}

func firstNLines(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) <= n {
		return strings.Join(lines, "\n")
	}
	return strings.Join(lines[:n], "\n") + "\n…"
}

// renderEnv formats the captured host environment as one compact line, skipping
// any field that wasn't determined (empty on a non-Linux host, for example).
func renderEnv(e *event.Environment) string {
	if e == nil {
		return ""
	}
	var parts []string
	if e.Distro != "" {
		parts = append(parts, e.Distro)
	}
	if e.Kernel != "" {
		parts = append(parts, "kernel "+e.Kernel)
	}
	if e.Arch != "" {
		parts = append(parts, e.Arch)
	}
	if e.BpftraceVersion != "" {
		parts = append(parts, "bpftrace "+e.BpftraceVersion)
	}
	if e.BTF {
		parts = append(parts, "BTF")
	}
	if e.ProbeCount > 0 {
		parts = append(parts, fmt.Sprintf("%d probes", e.ProbeCount))
	}
	return strings.Join(parts, " · ")
}

func trimJSONArray(s string) string {
	s = strings.TrimPrefix(strings.TrimSuffix(s, "]"), "[")
	return strings.ReplaceAll(s, "\"", "")
}
