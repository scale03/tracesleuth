package cost

import (
	"testing"

	"tracesleuth/internal/catalog"
)

func TestScriptAggregates(t *testing.T) {
	yes := []string{
		"kprobe:tcp_connect { @=count(); }",
		"kprobe:x { @lat = hist(nsecs); }",
		"tracepoint:syscalls:sys_enter_openat { @[comm] = count(); }",
	}
	no := []string{
		`kprobe:tcp_connect { printf("%d\n", pid); }`,
		"kprobe:x { print(comm); }",
	}
	for _, s := range yes {
		if !ScriptAggregates(s) {
			t.Errorf("expected aggregation in %q", s)
		}
	}
	for _, s := range no {
		if ScriptAggregates(s) {
			t.Errorf("did not expect aggregation in %q", s)
		}
	}
}

func TestRateFromAttachPoints(t *testing.T) {
	c := catalog.Default()
	// sys_enter_read is high-frequency in the default catalog.
	if e := Of(c, []string{"tcp_connect", "sys_enter_read"}, "printf(1)", false, false); e.Rate != RateHigh {
		t.Errorf("a high-frequency point should make the probe high-rate, got %s", e.Rate)
	}
	// tcp_connect alone is moderate.
	if e := Of(c, []string{"tcp_connect"}, "printf(1)", false, false); e.Rate != RateModerate {
		t.Errorf("want moderate, got %s", e.Rate)
	}
	// An attach point outside the catalog can't be rated.
	if e := Of(c, []string{"some_unknown_fn"}, "printf(1)", false, false); e.Rate != RateUnknown {
		t.Errorf("want unknown, got %s", e.Rate)
	}
}

func TestAggregatedVolumeIsBounded(t *testing.T) {
	c := catalog.Default()
	// Even at a high-frequency point, aggregation makes the volume bounded.
	e := Of(c, []string{"sys_enter_read"}, "@[comm] = count();", false, false)
	if !e.Aggregated || e.Rate != RateHigh {
		t.Fatalf("setup wrong: %+v", e)
	}
	if got := e.Volume; got == "" || got[:7] != "bounded" {
		t.Fatalf("aggregated high-rate probe should be bounded, got %q", got)
	}
}

func TestFilteredNoteDiffersFromUnfiltered(t *testing.T) {
	c := catalog.Default()
	filtered := Of(c, []string{"tcp_connect"}, "printf(1)", true, false)
	unfiltered := Of(c, []string{"tcp_connect"}, "printf(1)", false, false)
	if !filtered.Filtered || unfiltered.Filtered {
		t.Fatalf("filter flag not carried through: %+v %+v", filtered, unfiltered)
	}
	if filtered.Volume == unfiltered.Volume {
		t.Error("a pid/comm filter should change the volume estimate")
	}
}
