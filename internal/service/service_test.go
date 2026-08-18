package service

import (
	"context"
	"strings"
	"testing"

	"tracesleuth/internal/catalog"
	"tracesleuth/internal/event"
	"tracesleuth/internal/exec"
)

func newSvc(t *testing.T) (*Service, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := New(Config{
		DataDir: dir, Host: "test-host", Executor: exec.NewMock(), Catalog: catalog.Default(),
		// Deterministic environment so tests never shell out to the host.
		CaptureEnv: func() event.Environment {
			return event.Environment{Kernel: "6.1.0-test", Distro: "TestOS", Arch: "amd64", BpftraceVersion: "0.24.2", BTF: true, ProbeCount: 1234}
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, dir
}

func TestEndToEndChainReconstructable(t *testing.T) {
	s, _ := newSvc(t)
	ctx := context.Background()

	inv, err := s.Open(Identity{Name: "bot:agent-x", Roles: []string{"reliability-team"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Hypothesis(inv, "tcp_connect latency correlates with openat storms"); err != nil {
		t.Fatal(err)
	}
	rep, err := s.RunProbe(ctx, inv, ProbeRequest{
		ProbeTypes:   []string{"kprobe"},
		AttachPoints: []string{"tcp_connect"},
		ScriptText:   "kprobe:tcp_connect { @start[tid] = nsecs; }",
		DurationS:    30,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Ran || rep.Decision != "allow" {
		t.Fatalf("expected allowed run, got decision=%s ran=%v reasons=%v", rep.Decision, rep.Ran, rep.Reasons)
	}
	if err := s.Close_(inv, "confirmed: log rotation openat storm"); err != nil {
		t.Fatal(err)
	}

	// Reconstruct the whole chain from the SQLite index alone (Phase 1 goal).
	iv, ok, err := s.Store().Get(inv)
	if err != nil || !ok {
		t.Fatalf("investigation not in index: ok=%v err=%v", ok, err)
	}
	if iv.Status != "closed" || iv.AgentIdentity != "bot:agent-x" {
		t.Fatalf("unexpected investigation row: %+v", iv)
	}
	if iv.Hypothesis == "" || iv.Conclusion == "" {
		t.Fatal("hypothesis/conclusion missing from index")
	}
	if len(iv.Probes) != 1 {
		t.Fatalf("expected 1 probe, got %d", len(iv.Probes))
	}
	p := iv.Probes[0]
	if p.PolicyDecision != "allow" || !p.ExitCode.Valid || p.OutputSHA256 == "" || p.ScriptText == "" {
		t.Fatalf("probe row missing traceability fields: %+v", p)
	}

	// And the append log must verify as an intact hash chain.
	res, err := event.VerifyFile(s.LogsDir() + "/" + inv + ".jsonl")
	if err != nil {
		t.Fatalf("chain did not verify: %v", err)
	}
	// opened, environment, hypothesis, proposed, decision, started, ended, closed
	// = 8 lines.
	if res.Lines != 8 {
		t.Fatalf("expected 8 audit lines, got %d", res.Lines)
	}
}

func TestDeniedProbeDoesNotRun(t *testing.T) {
	s, _ := newSvc(t)
	inv, _ := s.Open(Identity{Name: "bot:x"})
	s.Hypothesis(inv, "syscall storm")

	// High-frequency attach point with raw per-event output → denied.
	rep, err := s.RunProbe(context.Background(), inv, ProbeRequest{
		ProbeTypes:   []string{"tracepoint"},
		AttachPoints: []string{"sys_enter_read"},
		ScriptText:   `tracepoint:syscalls:sys_enter_read { printf("%d\n", pid); }`,
		DurationS:    10,
		FilterPID:    true,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Ran || rep.Decision != "deny" {
		t.Fatalf("expected denial with no run, got ran=%v decision=%s", rep.Ran, rep.Decision)
	}
	if !containsSubstr(rep.Reasons, "aggregation") {
		t.Fatalf("expected actionable aggregation reason, got %v", rep.Reasons)
	}
	// The denial must be in the audit log, and the chain still valid.
	if _, err := event.VerifyFile(s.LogsDir() + "/" + inv + ".jsonl"); err != nil {
		t.Fatalf("chain invalid after denial: %v", err)
	}
	iv, _, _ := s.Store().Get(inv)
	if len(iv.Probes) != 1 || iv.Probes[0].PolicyDecision != "deny" {
		t.Fatalf("denied probe not recorded correctly: %+v", iv.Probes)
	}
}

func TestReindexReproducesState(t *testing.T) {
	s, _ := newSvc(t)
	inv, _ := s.Open(Identity{Name: "bot:x"})
	s.Hypothesis(inv, "h")
	s.RunProbe(context.Background(), inv, ProbeRequest{
		ProbeTypes: []string{"kprobe"}, AttachPoints: []string{"tcp_connect"},
		ScriptText: "kprobe:tcp_connect { @=count(); }", DurationS: 20, FilterPID: true,
	}, nil)
	s.Close_(inv, "done")

	before, _, _ := s.Store().Get(inv)
	// Blow away the index and rebuild purely from JSONL.
	if _, err := s.Reindex(); err != nil {
		t.Fatal(err)
	}
	after, ok, _ := s.Store().Get(inv)
	if !ok {
		t.Fatal("investigation vanished after reindex")
	}
	if before.Status != after.Status || before.Hypothesis != after.Hypothesis ||
		len(before.Probes) != len(after.Probes) || before.Conclusion != after.Conclusion {
		t.Fatalf("reindex changed state:\n before=%+v\n after=%+v", before, after)
	}
}

func containsSubstr(ss []string, sub string) bool {
	for _, s := range ss {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
