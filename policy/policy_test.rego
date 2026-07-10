# Paired tests for policy.rego. Every rule has at least one allow and one deny
# case — per project convention, no policy rule merges without a test, because
# this is the one place test coverage has direct safety consequences.
#
# Run: opa test ./policy/...
package investigation

import rego.v1

test_allow_simple_scoped_kprobe if {
	allow with input as {
		"action": {
			"probe_types": ["kprobe"],
			"attach_points": ["tcp_connect"],
			"script_text": "kprobe:tcp_connect { @start[tid] = nsecs; }",
			"duration_s": 30,
			"filters": {},
		},
		"context": {"probe_count": 0, "running_on_host": 0},
	}
}

test_deny_unlisted_probe_type if {
	some msg in deny with input as base_input([], "watchpoint", "tcp_connect", "watchpoint:x { }", 10)
	contains(msg, "not on the allow-list")
}

test_deny_unlisted_attach_point if {
	some msg in deny with input as base_input([], "kprobe", "do_evil", "kprobe:do_evil { }", 10)
	contains(msg, "not whitelisted")
}

test_deny_over_max_duration if {
	some msg in deny with input as base_input(["pid"], "kprobe", "tcp_connect", "kprobe:tcp_connect { @=count(); }", 9999)
	contains(msg, "exceeds the maximum")
}

test_deny_high_frequency_without_aggregation if {
	some msg in deny with input as base_input(["pid"], "tracepoint", "sys_enter_read", "tracepoint:syscalls:sys_enter_read { printf(\"x\") }", 10)
	contains(msg, "requires an aggregation")
}

test_allow_high_frequency_with_aggregation if {
	allow with input as base_input(["comm"], "tracepoint", "sys_enter_read", "tracepoint:syscalls:sys_enter_read { @[comm] = count(); }", 10)
}

test_deny_first_probe_unscoped_long if {
	some msg in deny with input as {
		"action": {
			"probe_types": ["kprobe"], "attach_points": ["tcp_connect"],
			"script_text": "kprobe:tcp_connect { printf(\"x\") }", "duration_s": 120, "filters": {},
		},
		"context": {"probe_count": 0, "running_on_host": 0},
	}
	contains(msg, "first probe")
}

test_allow_long_probe_after_first if {
	allow with input as {
		"action": {
			"probe_types": ["kprobe"], "attach_points": ["tcp_connect"],
			"script_text": "kprobe:tcp_connect { printf(\"x\") }", "duration_s": 120, "filters": {},
		},
		"context": {"probe_count": 1, "running_on_host": 0},
	}
}

test_deny_concurrency_cap if {
	some msg in deny with input as {
		"action": {
			"probe_types": ["kprobe"], "attach_points": ["tcp_connect"],
			"script_text": "kprobe:tcp_connect { @=count(); }", "duration_s": 10, "filters": {"pid": true},
		},
		"context": {"probe_count": 2, "running_on_host": 4},
	}
	contains(msg, "already has")
}

# base_input builds a single-probe input with the given filters set true.
base_input(filter_names, ptype, attach, script, dur) := {
	"action": {
		"probe_types": [ptype],
		"attach_points": [attach],
		"script_text": script,
		"duration_s": dur,
		"filters": {name: true | some name in filter_names},
	},
	"context": {"probe_count": 1, "running_on_host": 0},
}
