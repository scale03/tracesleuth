// Package policy is the embedded decision layer that runs right before a probe
// starts. It mirrors, rule-for-rule, the Rego in /policy (the reviewable spec):
// probe-type allow-list, duration cap, high-frequency-requires-aggregation, and
// coarse-then-narrow first-probe scoping. Keeping it as a Go implementation lets
// the daemon decide without an OPA process on the host; the .rego files are the
// safety-reviewed source of truth and are exercised by opa test in CI.
//
// Every call produces a Decision that is logged verbatim as a policy_decision
// event — including denials — with an actionable reason string the agent can
// act on without guessing.
package policy

import (
	"fmt"
	"regexp"

	"tracesleuth/internal/catalog"
)

// Filters mirrors the bpftrace scoping an agent can declare up front.
type Filters struct {
	PID  bool `json:"pid"`
	Comm bool `json:"comm"`
}

// Action is the probe under evaluation.
type Action struct {
	ProbeTypes   []string `json:"probe_types"`
	AttachPoints []string `json:"attach_points"`
	ScriptText   string   `json:"script_text"`
	DurationS    int      `json:"duration_s"`
	Filters      Filters  `json:"filters"`
}

// Context is investigation state policy needs but that isn't in the action.
type Context struct {
	ProbeCount     int `json:"probe_count"`     // probes already run in this investigation
	RunningOnHost  int `json:"running_on_host"` // probes currently executing on this host
}

// Input is the full decision input, matching the OPA input document shape.
type Input struct {
	Action  Action  `json:"action"`
	Context Context `json:"context"`
}

// Decision is the verdict. Allow is true only when Reasons is empty.
type Decision struct {
	Allow         bool     `json:"allow"`
	Reasons       []string `json:"reasons"`
	BundleVersion string   `json:"policy_bundle_version"`
}

// Verdict renders the decision as the string stored in the audit log.
func (d Decision) Verdict() string {
	if d.Allow {
		return "allow"
	}
	return "deny"
}

// aggregation matches any bpftrace aggregation construct: count(), sum(),
// hist()/lhist(), avg/min/max, or a map assignment like @foo[...]. Its presence
// is what distinguishes a summarizing script from one that floods per-event.
var aggregation = regexp.MustCompile(`count\(\)|sum\(|hist\(|avg\(|min\(|max\(|@\w*\[`)

func usesAggregation(script string) bool {
	return aggregation.MatchString(script)
}

// Evaluate applies all rules and returns a single Decision. Rules are additive:
// every violated rule contributes its own reason, so an agent sees everything
// wrong at once instead of fixing one and rediscovering the next.
func Evaluate(in Input, cat catalog.Catalog) Decision {
	d := Decision{Allow: true, BundleVersion: cat.BundleVersion}

	// Rule: probe types must be on the allow-list.
	for _, pt := range in.Action.ProbeTypes {
		if !cat.AllowsProbeType(pt) {
			d.deny("probe type %q is not on the allow-list %v", pt, cat.ProbeTypes)
		}
	}

	// Rule: attach points must be on the allow-list.
	for _, ap := range in.Action.AttachPoints {
		if _, ok := cat.Lookup(ap); !ok {
			d.deny("attach point %q is not whitelisted; call list_probe_catalog for allowed points", ap)
		}
	}

	// Rule: duration must be within the hard cap.
	if in.Action.DurationS > cat.MaxDuration {
		d.deny("duration %ds exceeds the maximum of %ds", in.Action.DurationS, cat.MaxDuration)
	}

	// Rule: concurrency cap per host.
	if in.Context.RunningOnHost >= cat.MaxConcurrent {
		d.deny("host already has %d probes running (max %d); wait for one to finish", in.Context.RunningOnHost, cat.MaxConcurrent)
	}

	// Rule (shape linter): high-frequency attach points require an aggregation,
	// not raw per-event output — this is what stops output floods at the source.
	for _, ap := range in.Action.AttachPoints {
		if cat.IsHighFrequency(ap) && !usesAggregation(in.Action.ScriptText) {
			d.deny("attach point %q is high-frequency and requires an aggregation (count/sum/hist/map), not raw per-event output", ap)
		}
	}

	// Rule (coarse-then-narrow): the first probe of an investigation may not be
	// a long, unscoped capture. It must be short, or filtered, or aggregated.
	if in.Context.ProbeCount == 0 &&
		in.Action.DurationS > cat.DefaultDuration &&
		!in.Action.Filters.PID && !in.Action.Filters.Comm &&
		!usesAggregation(in.Action.ScriptText) {
		d.deny("first probe in an investigation must be a short (≤%ds), filtered (pid/comm), or aggregated pass — no unscoped long captures on the first try", cat.DefaultDuration)
	}

	return d
}

func (d *Decision) deny(format string, args ...any) {
	d.Allow = false
	d.Reasons = append(d.Reasons, fmt.Sprintf(format, args...))
}
