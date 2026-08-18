// Package cost gives a pre-execution estimate of how expensive a probe is likely
// to be, from catalog metadata and the script alone. This is the static M1
// heuristic: it knows which attach points are high-frequency and whether the
// script aggregates or is filtered, but nothing about the live host. A
// host-aware estimate (a short canary measurement against real event rates)
// replaces the volume guess in a later phase.
package cost

import (
	"regexp"

	"tracesleuth/internal/catalog"
)

// Rate is a qualitative event-rate tier for an attach point.
type Rate string

const (
	RateModerate Rate = "moderate"
	RateHigh     Rate = "high"
	RateUnknown  Rate = "unknown"
)

// Estimate is a pre-execution cost estimate. It is deliberately qualitative:
// without a host measurement, a number would imply a precision it doesn't have.
type Estimate struct {
	Rate       Rate // the fastest attach point's tier drives the estimate
	Aggregated bool // the script reduces output in-kernel (map/aggregation)
	Filtered   bool // a pid/comm filter narrows the stream
	Volume     string
	Note       string
}

// aggFn matches an aggregation function call or a map write — either means the
// script summarizes in-kernel rather than printing one line per event.
var aggFn = regexp.MustCompile(`@\w*\s*(\[[^\]]*\])?\s*=|\b(count|sum|hist|lhist|avg|min|max|stats)\s*\(`)

// ScriptAggregates reports whether a script reduces its output in-kernel.
func ScriptAggregates(script string) bool { return aggFn.MatchString(script) }

// Of derives the static cost estimate for a probe.
func Of(c catalog.Catalog, attachPoints []string, script string, filterPID, filterComm bool) Estimate {
	e := Estimate{
		Rate:       RateModerate,
		Aggregated: ScriptAggregates(script),
		Filtered:   filterPID || filterComm,
	}
	// The fastest attach point sets the tier: any high-frequency point makes the
	// whole probe high-rate; an unknown point (not in the catalog) can't be rated.
	sawUnknown := false
	for _, ap := range attachPoints {
		if known, ok := c.Lookup(ap); ok {
			if known.HighFrequency {
				e.Rate = RateHigh
			}
		} else {
			sawUnknown = true
		}
	}
	if e.Rate != RateHigh && sawUnknown {
		e.Rate = RateUnknown
	}

	switch {
	case e.Aggregated:
		e.Volume = "bounded — output is a kernel-side summary; size is independent of event rate"
		e.Note = "aggregated: safe to run at the full duration"
	case e.Rate == RateHigh:
		e.Volume = "large — per-event output at a high-frequency point; expect heavy truncation"
		e.Note = "high-frequency point without aggregation; policy will likely deny — aggregate instead"
	case e.Filtered:
		e.Volume = "low to moderate — per-event output, narrowed by a pid/comm filter"
		e.Note = "filtered per-event capture: fine for a short window"
	case e.Rate == RateUnknown:
		e.Volume = "unknown — attach point is not in the catalog, so its rate can't be estimated"
		e.Note = "unrated attach point; keep the duration short until you've seen the rate"
	default:
		e.Volume = "moderate — per-event output at a moderate-rate point"
		e.Note = "consider a pid/comm filter or an aggregation to keep output bounded"
	}
	return e
}
