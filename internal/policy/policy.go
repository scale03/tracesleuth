// Package policy is the decision layer that runs right before a probe starts.
//
// As of bundle 2026.07.02 the daemon evaluates the Rego in /policy/policy.rego
// at RUNTIME via the embedded OPA SDK (see engine.go) rather than a hand-written
// Go mirror. The posture is DEFAULT-ALLOW + DENY-LIST: full bpftrace capability,
// narrowed only by the deny rules in the policy. This file defines the input and
// decision shapes shared by the engine, the service, and the OPA input document;
// engine.go holds the evaluation.
//
// Every call produces a Decision that is logged verbatim as a policy_decision
// event — including denials — with actionable reason strings the agent can act on
// without guessing.
package policy

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
	ProbeCount    int `json:"probe_count"`     // probes already run in this investigation
	RunningOnHost int `json:"running_on_host"` // probes currently executing on this host
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
