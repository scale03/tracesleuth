# package investigation — the reviewable policy spec for TraceSleuth.
#
# This is the SAFETY-CRITICAL source of truth for what a probe is allowed to do.
# The daemon currently enforces an identical rule set implemented in Go
# (internal/policy) so it can decide without an OPA process on the host; this
# file is what humans review and what `opa test ./policy/...` exercises in CI.
# If you change a rule here, change internal/policy to match (and vice versa) —
# the paired tests in both places are what keep them from drifting.
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
# The allow-lists below mirror internal/catalog.Default(). In Phase 4 they become
# a synced data document (data.catalog) generated from the host's real probes.
package investigation

import rego.v1

# --- catalog (mirror of internal/catalog.Default) ---------------------------

allowed_probe_types := {"kprobe", "kretprobe", "tracepoint", "uprobe", "interval", "profile"}

allowed_attach_points := {
	"tcp_connect", "tcp_retransmit_skb",
	"sys_enter_openat", "sys_enter_read", "sys_enter_write", "sys_enter_execve",
	"block_rq_issue", "block_rq_complete",
	"sched_switch", "sched_process_exec",
}

high_frequency_points := {
	"sys_enter_openat", "sys_enter_read", "sys_enter_write",
	"block_rq_complete", "sched_switch",
}

default_duration := 30
max_duration := 300
max_concurrent := 4

# --- helpers ----------------------------------------------------------------

uses_aggregation(script) if regex.match(`count\(\)|sum\(|hist\(|avg\(|min\(|max\(|@\w*\[`, script)

# --- rules: each violated rule contributes one actionable reason ------------

deny contains msg if {
	some pt in input.action.probe_types
	not allowed_probe_types[pt]
	msg := sprintf("probe type %q is not on the allow-list", [pt])
}

deny contains msg if {
	some ap in input.action.attach_points
	not allowed_attach_points[ap]
	msg := sprintf("attach point %q is not whitelisted; call list_probe_catalog for allowed points", [ap])
}

deny contains msg if {
	input.action.duration_s > max_duration
	msg := sprintf("duration %ds exceeds the maximum of %ds", [input.action.duration_s, max_duration])
}

deny contains msg if {
	input.context.running_on_host >= max_concurrent
	msg := sprintf("host already has %d probes running (max %d); wait for one to finish", [input.context.running_on_host, max_concurrent])
}

# high-frequency attach points require an aggregation, not raw per-event output.
deny contains msg if {
	some ap in input.action.attach_points
	high_frequency_points[ap]
	not uses_aggregation(input.action.script_text)
	msg := sprintf("attach point %q is high-frequency and requires an aggregation (count/sum/hist/map), not raw per-event output", [ap])
}

# coarse-then-narrow: the first probe of an investigation may not be a long,
# unscoped, unaggregated capture.
deny contains msg if {
	input.context.probe_count == 0
	input.action.duration_s > default_duration
	not input.action.filters.pid
	not input.action.filters.comm
	not uses_aggregation(input.action.script_text)
	msg := "first probe in an investigation must be a short, filtered (pid/comm), or aggregated pass — no unscoped long captures on the first try"
}

# allow iff nothing denied.
default allow := false

allow if count(deny) == 0
