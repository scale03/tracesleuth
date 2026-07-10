package policy

import (
	"context"
	"os"
	"strings"
	"testing"

	"tracesleuth/internal/catalog"
)

// engineFrom builds an Engine from the embedded policy and a catalog's data doc,
// optionally with extra deny-lists layered on for the deny-list tests.
func engineFrom(t *testing.T, deniedAttach, deniedTypes []string) *Engine {
	t.Helper()
	c := catalog.Default()
	c.DeniedAttachPoints = deniedAttach
	c.DeniedProbeTypes = deniedTypes
	e, err := NewEngine(context.Background(), "", c.AsData(), c.BundleVersion)
	if err != nil {
		t.Fatalf("build engine: %v", err)
	}
	return e
}

func eval(t *testing.T, e *Engine, in Input) Decision {
	t.Helper()
	d, err := e.Evaluate(context.Background(), in)
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	return d
}

// Default-allow: an attach point nobody ever listed still runs. This is the whole
// point of the posture change — capability is open, policy only carves out.
func TestAllowsArbitraryUnlistedPoint(t *testing.T) {
	e := engineFrom(t, nil, nil)
	d := eval(t, e, Input{
		Action: Action{
			ProbeTypes:   []string{"kprobe"},
			AttachPoints: []string{"vfs_rename"}, // never in the catalog
			ScriptText:   `kprobe:vfs_rename { printf("%s\n", comm); }`,
			DurationS:    30,
		},
		Context: Context{ProbeCount: 1},
	})
	if !d.Allow {
		t.Fatalf("expected allow for arbitrary point, got deny: %v", d.Reasons)
	}
}

func TestDenyExplicitlyBlacklistedPoint(t *testing.T) {
	e := engineFrom(t, []string{"do_nefarious_thing"}, nil)
	d := eval(t, e, Input{
		Action: Action{
			ProbeTypes:   []string{"kprobe"},
			AttachPoints: []string{"do_nefarious_thing"},
			ScriptText:   `kprobe:do_nefarious_thing { }`,
			DurationS:    10,
			Filters:      Filters{PID: true},
		},
		Context: Context{ProbeCount: 1},
	})
	if d.Allow {
		t.Fatal("expected deny for blacklisted attach point")
	}
	assertReason(t, d, "explicitly denied")
}

func TestDenyBlacklistedProbeType(t *testing.T) {
	e := engineFrom(t, nil, []string{"uprobe"})
	d := eval(t, e, Input{
		Action: Action{
			ProbeTypes:   []string{"uprobe"},
			AttachPoints: []string{"/bin/bash:readline"},
			ScriptText:   `uprobe:/bin/bash:readline { }`,
			DurationS:    10,
			Filters:      Filters{PID: true},
		},
		Context: Context{ProbeCount: 1},
	})
	if d.Allow {
		t.Fatal("expected deny for blacklisted probe type")
	}
	assertReason(t, d, "explicitly denied")
}

func TestDenyOverMaxDuration(t *testing.T) {
	e := engineFrom(t, nil, nil)
	d := eval(t, e, Input{
		Action: Action{
			ProbeTypes: []string{"kprobe"}, AttachPoints: []string{"tcp_connect"},
			ScriptText: "kprobe:tcp_connect { @[comm]=count(); }", DurationS: 9999,
			Filters: Filters{PID: true},
		},
		Context: Context{ProbeCount: 1},
	})
	if d.Allow {
		t.Fatal("expected deny for over-max duration")
	}
	assertReason(t, d, "exceeds the maximum")
}

func TestDenyHighFrequencyWithoutAggregation(t *testing.T) {
	e := engineFrom(t, nil, nil)
	d := eval(t, e, Input{
		Action: Action{
			ProbeTypes: []string{"tracepoint"}, AttachPoints: []string{"sys_enter_read"},
			ScriptText: `tracepoint:syscalls:sys_enter_read { printf("%d\n", pid); }`, DurationS: 10,
			Filters: Filters{PID: true},
		},
		Context: Context{ProbeCount: 1},
	})
	if d.Allow {
		t.Fatal("expected deny: high-frequency point needs aggregation")
	}
	assertReason(t, d, "requires an aggregation")
}

func TestAllowHighFrequencyWithAggregation(t *testing.T) {
	e := engineFrom(t, nil, nil)
	d := eval(t, e, Input{
		Action: Action{
			ProbeTypes: []string{"tracepoint"}, AttachPoints: []string{"sys_enter_read"},
			ScriptText: `tracepoint:syscalls:sys_enter_read { @reads[comm] = count(); }`, DurationS: 10,
			Filters: Filters{Comm: true},
		},
		Context: Context{ProbeCount: 1},
	})
	if !d.Allow {
		t.Fatalf("expected allow for aggregated high-frequency probe: %v", d.Reasons)
	}
}

func TestDenyFirstProbeUnscopedLong(t *testing.T) {
	e := engineFrom(t, nil, nil)
	d := eval(t, e, Input{
		Action: Action{
			ProbeTypes: []string{"kprobe"}, AttachPoints: []string{"tcp_connect"},
			ScriptText: `kprobe:tcp_connect { printf("%d\n", pid); }`, DurationS: 120,
		},
		Context: Context{ProbeCount: 0},
	})
	if d.Allow {
		t.Fatal("expected deny for unscoped long first probe")
	}
	assertReason(t, d, "first probe")
}

func TestAllowLongProbeAfterFirst(t *testing.T) {
	e := engineFrom(t, nil, nil)
	d := eval(t, e, Input{
		Action: Action{
			ProbeTypes: []string{"kprobe"}, AttachPoints: []string{"tcp_connect"},
			ScriptText: `kprobe:tcp_connect { printf("%d\n", pid); }`, DurationS: 120,
		},
		Context: Context{ProbeCount: 1},
	})
	if !d.Allow {
		t.Fatalf("expected allow for follow-up long probe: %v", d.Reasons)
	}
}

func TestDenyConcurrencyCap(t *testing.T) {
	e := engineFrom(t, nil, nil)
	d := eval(t, e, Input{
		Action:  Action{ProbeTypes: []string{"kprobe"}, AttachPoints: []string{"tcp_connect"}, ScriptText: "kprobe:tcp_connect { @=count(); }", DurationS: 10, Filters: Filters{PID: true}},
		Context: Context{ProbeCount: 2, RunningOnHost: 4},
	})
	if d.Allow {
		t.Fatal("expected deny at concurrency cap")
	}
	assertReason(t, d, "already has")
}

func TestMultipleReasonsAccumulate(t *testing.T) {
	// Blacklisted point AND over-duration AND concurrency: all reported at once.
	e := engineFrom(t, []string{"nope"}, nil)
	d := eval(t, e, Input{
		Action:  Action{ProbeTypes: []string{"kprobe"}, AttachPoints: []string{"nope"}, ScriptText: "kprobe:nope { }", DurationS: 99999, Filters: Filters{PID: true}},
		Context: Context{ProbeCount: 1, RunningOnHost: 4},
	})
	if d.Allow || len(d.Reasons) < 3 {
		t.Fatalf("expected >=3 accumulated reasons, got %d: %v", len(d.Reasons), d.Reasons)
	}
}

// TestEmbeddedPolicyMatchesSpec guards the embedded copy against drift from the
// reviewable spec at /policy/policy.rego that CI runs `opa test` against.
func TestEmbeddedPolicyMatchesSpec(t *testing.T) {
	spec, err := os.ReadFile("../../policy/policy.rego")
	if err != nil {
		t.Fatalf("read spec: %v", err)
	}
	if strings.TrimRight(string(spec), "\n") != strings.TrimRight(EmbeddedPolicy(), "\n") {
		t.Fatal("internal/policy/policy.rego has drifted from /policy/policy.rego — copy the spec over")
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
