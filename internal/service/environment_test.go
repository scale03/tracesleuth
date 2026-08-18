package service

import (
	"strings"
	"testing"

	"tracesleuth/internal/event"
)

// Opening captures the environment as its own chain event, right after
// investigation_opened.
func TestOpenCapturesEnvironment(t *testing.T) {
	s, _ := newSvc(t)
	inv, err := s.Open(Identity{Name: "bot:x"})
	if err != nil {
		t.Fatal(err)
	}
	evs, err := event.ReadDir(s.LogsDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 2 || evs[0].Event != event.InvestigationOpened || evs[1].Event != event.EnvironmentCaptured {
		t.Fatalf("want opened then environment_captured, got %d events: %+v", len(evs), evs)
	}
	if evs[1].Environment == nil || evs[1].Environment.Kernel != "6.1.0-test" {
		t.Fatalf("environment not recorded on the event: %+v", evs[1].Environment)
	}
	_ = inv
}

// The environment projects onto the investigation row and survives a reindex
// from the JSONL source of truth.
func TestEnvironmentProjectedAndReindexed(t *testing.T) {
	s, _ := newSvc(t)
	inv, _ := s.Open(Identity{Name: "bot:x"})

	check := func(stage string) {
		iv, ok, err := s.Store().Get(inv)
		if err != nil || !ok {
			t.Fatalf("%s: get failed ok=%v err=%v", stage, ok, err)
		}
		if iv.Environment == nil {
			t.Fatalf("%s: environment missing from projection", stage)
		}
		if iv.Environment.Distro != "TestOS" || iv.Environment.ProbeCount != 1234 {
			t.Fatalf("%s: environment fields wrong: %+v", stage, iv.Environment)
		}
	}
	check("apply")
	if _, err := s.Reindex(); err != nil {
		t.Fatal(err)
	}
	check("reindex")
}

// show_investigation renders the environment as a compact line.
func TestDescribeShowsEnvironment(t *testing.T) {
	s, _ := newSvc(t)
	inv, _ := s.Open(Identity{Name: "bot:x"})
	s.Hypothesis(inv, "h")
	text, ok, err := s.Describe(inv)
	if err != nil || !ok {
		t.Fatalf("describe: ok=%v err=%v", ok, err)
	}
	for _, want := range []string{"TestOS", "kernel 6.1.0-test", "bpftrace 0.24.2", "1234 probes"} {
		if !strings.Contains(text, want) {
			t.Errorf("describe output missing %q:\n%s", want, text)
		}
	}
}
