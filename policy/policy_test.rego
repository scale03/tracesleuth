# Paired tests for policy.rego. Posture is default-allow + deny-list, so the
# suite covers: an arbitrary point is ALLOWED (capability is open), each deny
# rule fires (blacklist + every modality guard), and data.catalog is injected the
# way the daemon injects it at runtime.
#
# Run: opa test ./policy/...
package investigation

import rego.v1

# Mirrors internal/catalog.Default().AsData() with deny-lists populated for the
# blacklist tests.
testcatalog := {
	"high_frequency": ["sys_enter_openat", "sys_enter_read", "sys_enter_write", "block_rq_complete", "sched_switch"],
	"denied_attach_points": ["do_nefarious_thing"],
	"denied_probe_types": ["watchpoint"],
	"default_duration": 30,
	"max_duration": 300,
	"max_concurrent": 4,
}

# Default-allow: a point that was never in any catalog still runs.
test_allow_arbitrary_unlisted_point if {
	allow with input as base_input([], "kprobe", "vfs_rename", "kprobe:vfs_rename { printf(\"x\") }", 30)
		with data.catalog as testcatalog
}

test_deny_blacklisted_attach_point if {
	some msg in deny with input as base_input([], "kprobe", "do_nefarious_thing", "kprobe:do_nefarious_thing { }", 10)
		with data.catalog as testcatalog
	contains(msg, "explicitly denied")
}

test_deny_blacklisted_probe_type if {
	some msg in deny with input as base_input([], "watchpoint", "0x0", "watchpoint:0x0:8:w { }", 10)
		with data.catalog as testcatalog
	contains(msg, "explicitly denied")
}

test_deny_over_max_duration if {
	some msg in deny with input as base_input(["pid"], "kprobe", "tcp_connect", "kprobe:tcp_connect { @=count() }", 9999)
		with data.catalog as testcatalog
	contains(msg, "exceeds the maximum")
}

test_deny_high_frequency_without_aggregation if {
	some msg in deny with input as base_input(["pid"], "tracepoint", "sys_enter_read", "tracepoint:syscalls:sys_enter_read { printf(\"x\") }", 10)
		with data.catalog as testcatalog
	contains(msg, "requires an aggregation")
}

test_allow_high_frequency_with_aggregation if {
	allow with input as base_input(["comm"], "tracepoint", "sys_enter_read", "tracepoint:syscalls:sys_enter_read { @[comm] = count() }", 10)
		with data.catalog as testcatalog
}

test_deny_first_probe_unscoped_long if {
	some msg in deny with input as {
		"action": {
			"probe_types": ["kprobe"], "attach_points": ["tcp_connect"],
			"script_text": "kprobe:tcp_connect { printf(\"x\") }", "duration_s": 120, "filters": {},
		},
		"context": {"probe_count": 0, "running_on_host": 0},
	}
		with data.catalog as testcatalog
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
		with data.catalog as testcatalog
}

test_deny_concurrency_cap if {
	some msg in deny with input as {
		"action": {
			"probe_types": ["kprobe"], "attach_points": ["tcp_connect"],
			"script_text": "kprobe:tcp_connect { @=count() }", "duration_s": 10, "filters": {"pid": true},
		},
		"context": {"probe_count": 2, "running_on_host": 4},
	}
		with data.catalog as testcatalog
	contains(msg, "already has")
}

# base_input builds a single-probe (non-first) input with the given filters set.
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
