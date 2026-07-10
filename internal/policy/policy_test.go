package policy

import (
	"strings"
	"testing"

	"tracesleuth/internal/catalog"
)

func cat() catalog.Catalog { return catalog.Default() }

func TestAllowsSimpleScopedKprobe(t *testing.T) {
	d := Evaluate(Input{
		Action: Action{
			ProbeTypes:   []string{"kprobe"},
			AttachPoints: []string{"tcp_connect"},
			ScriptText:   "kprobe:tcp_connect { @start[tid] = nsecs; }",
			DurationS:    30,
		},
	}, cat())
	if !d.Allow {
		t.Fatalf("expected allow, got deny: %v", d.Reasons)
	}
}

func TestDenyUnlistedProbeType(t *testing.T) {
	d := Evaluate(Input{Action: Action{
		ProbeTypes: []string{"watchpoint"}, AttachPoints: []string{"tcp_connect"},
		ScriptText: "watchpoint:0x0:8:w { }", DurationS: 10,
	}}, cat())
	if d.Allow {
		t.Fatal("expected deny for unlisted probe type")
	}
	assertReason(t, d, "not on the allow-list")
}

func TestDenyUnlistedAttachPoint(t *testing.T) {
	d := Evaluate(Input{Action: Action{
		ProbeTypes: []string{"kprobe"}, AttachPoints: []string{"do_nefarious_thing"},
		ScriptText: "kprobe:do_nefarious_thing { }", DurationS: 10,
	}}, cat())
	if d.Allow {
		t.Fatal("expected deny for unlisted attach point")
	}
	assertReason(t, d, "not whitelisted")
}

func TestDenyOverMaxDuration(t *testing.T) {
	d := Evaluate(Input{Action: Action{
		ProbeTypes: []string{"kprobe"}, AttachPoints: []string{"tcp_connect"},
		ScriptText: "kprobe:tcp_connect { @[comm]=count(); }", DurationS: 9999,
		Filters:    Filters{PID: true},
	}}, cat())
	if d.Allow {
		t.Fatal("expected deny for over-max duration")
	}
	assertReason(t, d, "exceeds the maximum")
}

func TestDenyHighFrequencyWithoutAggregation(t *testing.T) {
	d := Evaluate(Input{Action: Action{
		ProbeTypes: []string{"tracepoint"}, AttachPoints: []string{"sys_enter_read"},
		ScriptText: `tracepoint:syscalls:sys_enter_read { printf("%d\n", pid); }`, DurationS: 10,
		Filters:    Filters{PID: true},
	}}, cat())
	if d.Allow {
		t.Fatal("expected deny: high-frequency point needs aggregation")
	}
	assertReason(t, d, "requires an aggregation")
}

func TestAllowHighFrequencyWithAggregation(t *testing.T) {
	d := Evaluate(Input{Action: Action{
		ProbeTypes: []string{"tracepoint"}, AttachPoints: []string{"sys_enter_read"},
		ScriptText: `tracepoint:syscalls:sys_enter_read { @reads[comm] = count(); }`, DurationS: 10,
		Filters:    Filters{Comm: true},
	}}, cat())
	if !d.Allow {
		t.Fatalf("expected allow for aggregated high-frequency probe: %v", d.Reasons)
	}
}

func TestDenyFirstProbeUnscopedLong(t *testing.T) {
	// First probe (ProbeCount 0), long, no filter, no aggregation → denied.
	d := Evaluate(Input{
		Action: Action{
			ProbeTypes: []string{"kprobe"}, AttachPoints: []string{"tcp_connect"},
			ScriptText: `kprobe:tcp_connect { printf("%d\n", pid); }`, DurationS: 120,
		},
		Context: Context{ProbeCount: 0},
	}, cat())
	if d.Allow {
		t.Fatal("expected deny for unscoped long first probe")
	}
	assertReason(t, d, "first probe")
}

func TestAllowLongProbeAfterFirst(t *testing.T) {
	// Same long unscoped shape, but not the first probe → the coarse-then-narrow
	// rule no longer applies.
	d := Evaluate(Input{
		Action: Action{
			ProbeTypes: []string{"kprobe"}, AttachPoints: []string{"tcp_connect"},
			ScriptText: `kprobe:tcp_connect { printf("%d\n", pid); }`, DurationS: 120,
		},
		Context: Context{ProbeCount: 1},
	}, cat())
	if !d.Allow {
		t.Fatalf("expected allow for follow-up long probe: %v", d.Reasons)
	}
}

func TestDenyConcurrencyCap(t *testing.T) {
	d := Evaluate(Input{
		Action:  Action{ProbeTypes: []string{"kprobe"}, AttachPoints: []string{"tcp_connect"}, ScriptText: "kprobe:tcp_connect { @=count(); }", DurationS: 10, Filters: Filters{PID: true}},
		Context: Context{ProbeCount: 2, RunningOnHost: 4},
	}, cat())
	if d.Allow {
		t.Fatal("expected deny at concurrency cap")
	}
	assertReason(t, d, "already has")
}

func TestMultipleReasonsAccumulate(t *testing.T) {
	// Unlisted type AND over-duration AND unlisted attach: all reported at once.
	d := Evaluate(Input{Action: Action{
		ProbeTypes: []string{"watchpoint"}, AttachPoints: []string{"nope"},
		ScriptText: "watchpoint:x { }", DurationS: 99999,
	}}, cat())
	if d.Allow || len(d.Reasons) < 3 {
		t.Fatalf("expected >=3 accumulated reasons, got %d: %v", len(d.Reasons), d.Reasons)
	}
}

func assertReason(t *testing.T, d Decision, substr string) {
	t.Helper()
	for _, r := range d.Reasons {
		if strings.Contains(r, substr) {
			return
		}
	}
	t.Fatalf("expected a reason containing %q, got %v", substr, d.Reasons)
}
