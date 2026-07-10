package event

import (
	"path/filepath"
	"strings"
	"testing"
)

// writeChain appends a small valid investigation and returns the log path.
func writeChain(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	lg, err := OpenLog(dir, "inv_test")
	if err != nil {
		t.Fatal(err)
	}
	dur := 30
	seq := []Event{
		{Event: InvestigationOpened, AgentIdentity: "bot:x", Host: "h1"},
		{Event: HypothesisDeclared, Text: "latency spike from openat storm"},
		{Event: ProbeProposed, ProbeID: "p_1", ScriptText: "kprobe:tcp_connect { @=count(); }", ProbeTypes: []string{"kprobe"}, AttachPoints: []string{"tcp_connect"}, DurationS: &dur},
		{Event: PolicyDecision, ProbeID: "p_1", Decision: "allow"},
		{Event: ProbeStarted, ProbeID: "p_1", Pid: IntPtr(1234)},
		{Event: ProbeEnded, ProbeID: "p_1", ExitCode: IntPtr(0), OutputPath: "outputs/x.log"},
		{Event: InvestigationClosed, Conclusion: "confirmed"},
	}
	for _, e := range seq {
		if _, err := lg.Append(e); err != nil {
			t.Fatal(err)
		}
	}
	lg.Close()
	return dir, filepath.Join(dir, "inv_test.jsonl")
}

func TestVerifyIntactChain(t *testing.T) {
	_, path := writeChain(t)
	res, err := VerifyFile(path)
	if err != nil {
		t.Fatalf("expected intact chain, got: %v", err)
	}
	if res.Lines != 7 || !res.OK {
		t.Fatalf("expected 7 lines OK, got %+v", res)
	}
}

func TestVerifyDetectsTamper(t *testing.T) {
	_, path := writeChain(t)
	raw := readFile(t, path)
	// Flip a byte inside a value without touching the hash → recompute mismatch.
	tampered := strings.Replace(raw, "openat storm", "openat STORM", 1)
	if tampered == raw {
		t.Fatal("test setup: substitution did not change file")
	}
	writeFile(t, path, tampered)

	if _, err := VerifyFile(path); err == nil {
		t.Fatal("expected verification to FAIL on tampered content")
	} else if !strings.Contains(err.Error(), "altered") {
		t.Fatalf("expected an 'altered' error, got: %v", err)
	}
}

func TestVerifyDetectsDeletedLine(t *testing.T) {
	_, path := writeChain(t)
	lines := strings.Split(strings.TrimRight(readFile(t, path), "\n"), "\n")
	// Drop the policy_decision line (index 3) → seq gap.
	kept := append(append([]string{}, lines[:3]...), lines[4:]...)
	writeFile(t, path, strings.Join(kept, "\n")+"\n")

	if _, err := VerifyFile(path); err == nil {
		t.Fatal("expected verification to FAIL on a deleted line")
	} else if !strings.Contains(err.Error(), "seq") {
		t.Fatalf("expected a seq-gap error, got: %v", err)
	}
}

func TestReopenContinuesChain(t *testing.T) {
	dir, path := writeChain(t)
	// Reopen and append another line; the chain must stay valid.
	lg, err := OpenLog(dir, "inv_test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lg.Append(Event{Event: HypothesisDeclared, Text: "addendum"}); err != nil {
		t.Fatal(err)
	}
	lg.Close()
	res, err := VerifyFile(path)
	if err != nil {
		t.Fatalf("chain broke after reopen: %v", err)
	}
	if res.Lines != 8 {
		t.Fatalf("expected 8 lines after reopen-append, got %d", res.Lines)
	}
}
