// Package output shapes what a probe returns inline to the caller, separately
// from what is captured to disk. Policy decides what may run; this decides what
// comes back. The full output always lands in a file (referenced by the
// probe_ended audit event); the agent only ever sees a bounded summary inline
// and can ask for more with a cheap follow-up read of the same file.
package output

import (
	"fmt"
	"strings"
)

// MaxInlineBytes is the hard cap on inlined output. Anything larger is truncated
// with an explicit note rather than silently flooding the response.
const MaxInlineBytes = 50 * 1024

// headLines / tailLines control the head+tail window for non-aggregated streams.
const (
	headLines = 20
	tailLines = 5
)

// Summary is a shaped view of raw probe output.
type Summary struct {
	Text      string // what to show inline
	Truncated bool   // whether Text omits some of the raw output
	RawBytes  int    // size of the full captured output
	// Aggregations are the colon-delimited @maps parsed from the full output,
	// used to render a bar chart alongside the raw text.
	Aggregations []Aggregation
}

// Chart renders the parsed aggregations as bar charts, or "" if the probe
// produced no colon-delimited @map (a raw per-event stream or a bare histogram).
func (s Summary) Chart() string {
	if len(s.Aggregations) == 0 {
		return ""
	}
	return renderBars(s.Aggregations)
}

// Summarize returns a bounded, representative view of raw output. Aggregated
// output (bpftrace @maps / histograms) is usually small and kept whole up to the
// byte cap; a long per-event stream is reduced to head+tail so the shape is
// visible without the flood. Either way the result is capped at MaxInlineBytes.
func Summarize(raw []byte) Summary {
	s := Summary{RawBytes: len(raw)}
	text := string(raw)
	// Parse aggregations from the full output before truncation — @maps are small
	// and we want the chart to reflect every key, not just the head+tail window.
	s.Aggregations = parseAggregations(text)

	lines := strings.Split(strings.TrimRight(text, "\n"), "\n")
	if len(lines) > headLines+tailLines+1 {
		head := lines[:headLines]
		tail := lines[len(lines)-tailLines:]
		omitted := len(lines) - headLines - tailLines
		text = strings.Join(head, "\n") +
			fmt.Sprintf("\n… %d lines omitted (full output on disk) …\n", omitted) +
			strings.Join(tail, "\n")
		s.Truncated = true
	}

	if len(text) > MaxInlineBytes {
		text = text[:MaxInlineBytes] +
			fmt.Sprintf("\n… truncated at %d bytes (%d bytes total on disk) …", MaxInlineBytes, len(raw))
		s.Truncated = true
	}

	s.Text = text
	return s
}
