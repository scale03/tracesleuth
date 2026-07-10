# package investigation — the reviewable policy spec for TraceSleuth.
#
# POSTURE: DEFAULT-ALLOW + DENY-LIST. The daemon has full bpftrace capability;
# this policy is the ONLY gate that narrows it. A probe runs unless one of the
# deny rules below fires. There is no compiled allow-list anymore — capability is
# open, and policy carves out what is forbidden (explicit deny-lists) and under
# what modality (duration caps, high-frequency-must-aggregate, first-probe
# scoping, concurrency).
#
# This file is the SAFETY-CRITICAL source of truth. It is:
#   1. evaluated at RUNTIME by the daemon via the OPA Go SDK (internal/policy), and
#   2. exercised by `opa test ./policy/...` in CI.
# internal/policy/policy.rego is a byte-identical embedded copy used as the
# built-in fallback; a guard test (TestEmbeddedPolicyMatchesSpec) keeps them from
# drifting. Change this file and the copy together.
#
# Catalog data (caps, the high-frequency set, and the deny-lists) is injected as
# data.catalog by internal/catalog. It is overridable at runtime via
# TRACESLEUTH_CATALOG without recompiling — that, plus editing this file, is how
# policy is managed now.
#
# Input shape (matches internal/policy.Input):
#   input.action.probe_types    []string
#   input.action.attach_points  []string
#   input.action.script_text    string
#   input.action.duration_s     number
#   input.action.filters.pid    bool
#   input.action.filters.comm   bool
#   input.context.probe_count     number  # probes already run in this investigation
#   input.context.running_on_host number  # probes currently executing on this host
#
# Data shape (data.catalog, injected from internal/catalog.Catalog.AsData):
#   data.catalog.high_frequency        []string  # points that must aggregate
#   data.catalog.denied_attach_points  []string  # explicit carve-outs
#   data.catalog.denied_probe_types    []string  # explicit carve-outs
#   data.catalog.default_duration      number
#   data.catalog.max_duration          number
#   data.catalog.max_concurrent        number
package investigation

import rego.v1

# --- helpers ----------------------------------------------------------------

uses_aggregation(script) if regex.match(`count\(\)|sum\(|hist\(|avg\(|min\(|max\(|@\w*\[`, script)

# --- deny rules: each violated rule contributes one actionable reason -------

# explicit attach-point deny-list (carve-outs from otherwise-full capability).
deny contains msg if {
	some ap in input.action.attach_points
	ap in data.catalog.denied_attach_points
	msg := sprintf("attach point %q is explicitly denied by policy", [ap])
}

# explicit probe-type deny-list.
deny contains msg if {
	some pt in input.action.probe_types
	pt in data.catalog.denied_probe_types
	msg := sprintf("probe type %q is explicitly denied by policy", [pt])
}

# modality: duration must be within the hard cap.
deny contains msg if {
	input.action.duration_s > data.catalog.max_duration
	msg := sprintf("duration %ds exceeds the maximum of %ds", [input.action.duration_s, data.catalog.max_duration])
}

# modality: concurrency cap per host.
deny contains msg if {
	input.context.running_on_host >= data.catalog.max_concurrent
	msg := sprintf("host already has %d probes running (max %d); wait for one to finish", [input.context.running_on_host, data.catalog.max_concurrent])
}

# modality: high-frequency attach points require an aggregation, not raw output.
deny contains msg if {
	some ap in input.action.attach_points
	ap in data.catalog.high_frequency
	not uses_aggregation(input.action.script_text)
	msg := sprintf("attach point %q is high-frequency and requires an aggregation (count/sum/hist/map), not raw per-event output", [ap])
}

# modality (coarse-then-narrow): the first probe of an investigation may not be a
# long, unscoped, unaggregated capture.
deny contains msg if {
	input.context.probe_count == 0
	input.action.duration_s > data.catalog.default_duration
	not input.action.filters.pid
	not input.action.filters.comm
	not uses_aggregation(input.action.script_text)
	msg := "first probe in an investigation must be a short, filtered (pid/comm), or aggregated pass — no unscoped long captures on the first try"
}

# --- decision: default-allow, denied only if a rule fired -------------------

default allow := true

allow := false if count(deny) > 0
