package service

import (
	"context"
	"strings"
	"testing"
)

// The card threads hypothesis → probe (with its aggregation finding read back
// from the captured output) → conclusion.
func TestSummaryCardThreadsFinding(t *testing.T) {
	s, _ := newSvc(t)
	inv, _ := s.Open(Identity{Name: "bot:x"})
	s.Hypothesis(inv, "who churns openat")
	if _, err := s.RunProbe(context.Background(), inv, ProbeRequest{
		ProbeTypes:   []string{"tracepoint"},
		AttachPoints: []string{"sys_enter_openat"},
		ScriptText:   "tracepoint:syscalls:sys_enter_openat { @[comm] = count(); }",
		DurationS:    1,
	}, nil); err != nil {
		t.Fatal(err)
	}
	s.Close_(inv, "openat is dominated by the top process")

	card, ok, err := s.SummaryCard(inv)
	if err != nil || !ok {
		t.Fatalf("card: ok=%v err=%v", ok, err)
	}
	for _, want := range []string{"who churns openat", "```bpftrace", "finding:", "### Conclusion", "dominated by the top process"} {
		if !strings.Contains(card, want) {
			t.Errorf("card missing %q:\n%s", want, card)
		}
	}
	// The mock aggregation output should surface as a bar chart in the finding.
	if !strings.Contains(card, "█") {
		t.Errorf("expected an aggregation chart in the finding:\n%s", card)
	}
}

// A denied probe is shown as denied, and its "finding" says it never ran.
func TestSummaryCardMarksDeniedProbe(t *testing.T) {
	s, _ := newSvc(t)
	inv, _ := s.Open(Identity{Name: "bot:x"})
	s.Hypothesis(inv, "h")
	s.RunProbe(context.Background(), inv, ProbeRequest{
		ProbeTypes:   []string{"tracepoint"},
		AttachPoints: []string{"sys_enter_read"},
		ScriptText:   `tracepoint:syscalls:sys_enter_read { printf("%d\n", pid); }`,
		FilterPID:    true,
	}, nil)

	card, _, _ := s.SummaryCard(inv)
	if !strings.Contains(card, "deny") || !strings.Contains(card, "did not run") {
		t.Fatalf("denied probe not surfaced in card:\n%s", card)
	}
}

func TestSummaryCardUnknownID(t *testing.T) {
	s, _ := newSvc(t)
	_, ok, err := s.SummaryCard("nope")
	if err != nil || ok {
		t.Fatalf("unknown id should be ok=false, no error; got ok=%v err=%v", ok, err)
	}
}
