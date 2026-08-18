package service

import (
	"fmt"
	"strings"
)

// Render produces the Phase 8 tool-response shape: a one-line status, then the
// exact script in a fenced block, then the decision — in that order, so it stays
// legible even if a harness truncates long output. The script is always echoed
// back in the same response, never only written to the audit log, so whoever
// reads the transcript sees what ran without a separate lookup. On denial the
// actionable OPA-style reason is the response.
func (r ProbeReport) Render() string {
	var b strings.Builder

	if r.Decision == "deny" {
		fmt.Fprintf(&b, "PROBE DENIED — %s — investigation %s\n\n", head(r.ScriptText), r.InvestigationID)
		b.WriteString("```bpftrace\n" + strings.TrimRight(r.ScriptText, "\n") + "\n```\n\n")
		b.WriteString("decision: deny — reasons:\n")
		for _, reason := range r.Reasons {
			fmt.Fprintf(&b, "  • %s\n", reason)
		}
		return b.String()
	}

	backend := r.Backend
	if backend == "mock" {
		backend = "mock (no real kernel capture on this host)"
	}
	status := "PROBE COMPLETED"
	if r.TimedOut {
		status = "PROBE COMPLETED (stopped at duration deadline)"
	}
	fmt.Fprintf(&b, "%s — %s — decision: allow — backend: %s\n\n", status, head(r.ScriptText), backend)
	b.WriteString("```bpftrace\n" + strings.TrimRight(r.ScriptText, "\n") + "\n```\n\n")
	fmt.Fprintf(&b, "started at %s, pid %d, investigation %s, probe %s, exit %d\n",
		r.StartedAt, r.Pid, r.InvestigationID, r.ProbeID, r.ExitCode)
	fmt.Fprintf(&b, "full output: %s (%d bytes)\n", r.OutputPath, r.Summary.RawBytes)
	if chart := r.Summary.Chart(); chart != "" {
		b.WriteString("\n--- aggregations ---\n")
		b.WriteString(chart)
	}
	b.WriteString("\n--- output summary")
	if r.Summary.Truncated {
		b.WriteString(" (truncated — full capture on disk)")
	}
	b.WriteString(" ---\n")
	b.WriteString(r.Summary.Text)
	if !strings.HasSuffix(r.Summary.Text, "\n") {
		b.WriteString("\n")
	}
	return b.String()
}

// head returns the first meaningful line of a script for the status line.
func head(script string) string {
	for _, ln := range strings.Split(script, "\n") {
		ln = strings.TrimSpace(ln)
		if ln != "" {
			if len(ln) > 60 {
				return ln[:60] + "…"
			}
			return ln
		}
	}
	return "(empty script)"
}
