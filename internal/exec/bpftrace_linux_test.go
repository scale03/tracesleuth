//go:build linux

package exec

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// fakeBin writes an executable shell script and returns a Bpftrace pointed at it
// with sudo disabled, so the deadline/signal machinery can be exercised without
// bpftrace or root. The script ignores its script-file argument.
func fakeBin(t *testing.T, body string) *Bpftrace {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return &Bpftrace{BinPath: p, UseSudo: false, GracePeriod: 300 * time.Millisecond}
}

// A process that exits on its own before the deadline: no timeout, real exit
// code captured.
func TestRunNaturalExitCapturesCode(t *testing.T) {
	b := fakeBin(t, "exit 3")
	res, err := b.Run(context.Background(), Spec{ScriptText: "x { }", Duration: 5 * time.Second})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.TimedOut {
		t.Fatal("a natural exit must not be marked TimedOut")
	}
	if res.ExitCode != 3 {
		t.Fatalf("want exit code 3, got %d", res.ExitCode)
	}
	if res.Backend != "bpftrace" || res.Pid == 0 {
		t.Fatalf("result missing provenance: %+v", res)
	}
}

// At the deadline we SIGINT so bpftrace flushes and exits; a process that honors
// SIGINT is gone within the grace period, so no SIGKILL is needed.
func TestRunDeadlineInterrupts(t *testing.T) {
	b := fakeBin(t, "sleep 30")
	start := time.Now()
	res, err := b.Run(context.Background(), Spec{ScriptText: "x { }", Duration: 200 * time.Millisecond})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.TimedOut {
		t.Fatal("deadline stop must be marked TimedOut")
	}
	// Interrupted well before the 30s sleep and before the grace escalation.
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("deadline interrupt was slow: %s", d)
	}
}

// A process that ignores SIGINT must be escalated to SIGKILL after the grace
// period rather than running to completion.
func TestRunEscalatesToKill(t *testing.T) {
	b := fakeBin(t, "trap '' INT; sleep 30")
	b.GracePeriod = 250 * time.Millisecond
	start := time.Now()
	res, err := b.Run(context.Background(), Spec{ScriptText: "x { }", Duration: 200 * time.Millisecond})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.TimedOut {
		t.Fatal("killed run must be marked TimedOut")
	}
	d := time.Since(start)
	if d > 3*time.Second {
		t.Fatalf("SIGKILL escalation did not fire; ran for %s", d)
	}
	if d < 200*time.Millisecond {
		t.Fatalf("returned before the deadline could fire: %s", d)
	}
}

// Cancelling the context stops the run the same way the deadline does.
func TestRunContextCancelStops(t *testing.T) {
	b := fakeBin(t, "sleep 30")
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	res, err := b.Run(ctx, Spec{ScriptText: "x { }", Duration: 30 * time.Second})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !res.TimedOut {
		t.Fatal("context cancel must be marked TimedOut")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("context cancel was slow: %s", d)
	}
}

// DryRun rejects a statically-broken script before spawning the binary.
func TestDryRunStaticRejectBeforeExec(t *testing.T) {
	// BinPath does not exist: if DryRun tried to run it, we'd get an exec error
	// rather than the staticCheck error, so this also proves the short-circuit.
	b := &Bpftrace{BinPath: "/nonexistent/bpftrace", UseSudo: false}
	if err := b.DryRun(context.Background(), Spec{ScriptText: "  "}); err == nil {
		t.Fatal("DryRun accepted an empty script")
	}
}
