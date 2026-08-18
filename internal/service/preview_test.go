package service

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPreviewAllowsAndEstimates(t *testing.T) {
	s, _ := newSvc(t)
	rep, err := s.PreviewProbe(context.Background(), "", ProbeRequest{
		ProbeTypes:   []string{"kprobe"},
		AttachPoints: []string{"tcp_connect"},
		ScriptText:   "kprobe:tcp_connect { @=count(); }",
		DurationS:    20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Decision != "allow" {
		t.Fatalf("want allow, got %s reasons=%v", rep.Decision, rep.Reasons)
	}
	if !rep.Estimate.Aggregated {
		t.Error("aggregating script should be reported as aggregated")
	}
}

func TestPreviewDeniesLikeRun(t *testing.T) {
	s, _ := newSvc(t)
	rep, err := s.PreviewProbe(context.Background(), "", ProbeRequest{
		ProbeTypes:   []string{"tracepoint"},
		AttachPoints: []string{"sys_enter_read"},
		ScriptText:   `tracepoint:syscalls:sys_enter_read { printf("%d\n", pid); }`,
		DurationS:    10,
		FilterPID:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Decision != "deny" || !containsSubstr(rep.Reasons, "aggregation") {
		t.Fatalf("want denial with aggregation reason, got %s %v", rep.Decision, rep.Reasons)
	}
}

// A preview must not touch the audit log or the index — it is a look-ahead, not
// an event.
func TestPreviewRecordsNothing(t *testing.T) {
	s, dir := newSvc(t)
	inv, _ := s.Open(Identity{Name: "bot:x"})
	s.Hypothesis(inv, "h")

	before, _, _ := s.Store().Get(inv)
	logPath := filepath.Join(dir, "logs", inv+".jsonl")
	sizeBefore := fileSize(t, logPath)

	if _, err := s.PreviewProbe(context.Background(), inv, ProbeRequest{
		ProbeTypes:   []string{"kprobe"},
		AttachPoints: []string{"tcp_connect"},
		ScriptText:   "kprobe:tcp_connect { @=count(); }",
	}); err != nil {
		t.Fatal(err)
	}

	after, _, _ := s.Store().Get(inv)
	if len(after.Probes) != len(before.Probes) {
		t.Fatalf("preview added probe rows: before=%d after=%d", len(before.Probes), len(after.Probes))
	}
	if fileSize(t, logPath) != sizeBefore {
		t.Fatal("preview appended to the audit log")
	}
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Size()
}
