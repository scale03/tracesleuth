package service

import (
	"fmt"
	"strings"
)

// Describe renders an investigation's full reconstructed chain from the SQLite
// index as a text block, shared by the CLI (show) and the MCP server. ok is
// false if the id is unknown.
func (s *Service) Describe(invID string) (string, bool, error) {
	iv, ok, err := s.store.Get(invID)
	if err != nil || !ok {
		return "", ok, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "Investigation %s  [%s]\n", iv.ID, iv.Status)
	fmt.Fprintf(&b, "  host:       %s\n", iv.Host)
	fmt.Fprintf(&b, "  identity:   %s\n", iv.AgentIdentity)
	fmt.Fprintf(&b, "  opened:     %s\n", iv.OpenedAt)
	if iv.ClosedAt != "" {
		fmt.Fprintf(&b, "  closed:     %s\n", iv.ClosedAt)
	}
	fmt.Fprintf(&b, "  hypothesis: %s\n", iv.Hypothesis)
	if iv.Conclusion != "" {
		fmt.Fprintf(&b, "  conclusion: %s\n", iv.Conclusion)
	}
	fmt.Fprintf(&b, "\n  probes (%d):\n", len(iv.Probes))
	for _, p := range iv.Probes {
		fmt.Fprintf(&b, "  ─ %s  decision=%s", p.ID, p.PolicyDecision)
		if p.DurationS.Valid {
			fmt.Fprintf(&b, " duration=%ds", p.DurationS.Int64)
		}
		if p.ExitCode.Valid {
			fmt.Fprintf(&b, " exit=%d", p.ExitCode.Int64)
		}
		b.WriteByte('\n')
		fmt.Fprintf(&b, "      attach=%s types=%s\n", trimJSONArray(p.AttachPoints), trimJSONArray(p.ProbeTypes))
		fmt.Fprintf(&b, "      script: %s\n", firstLine(p.ScriptText))
		if p.OutputPath != "" {
			fmt.Fprintf(&b, "      output: %s  sha256=%.12s…\n", p.OutputPath, p.OutputSHA256)
		}
	}
	return b.String(), true, nil
}

func trimJSONArray(s string) string {
	s = strings.TrimPrefix(strings.TrimSuffix(s, "]"), "[")
	return strings.ReplaceAll(s, "\"", "")
}

func firstLine(s string) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\t", " ")
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 100 {
		return s[:100] + "…"
	}
	return s
}
