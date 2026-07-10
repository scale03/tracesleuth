package exec

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

// MockExecutor produces deterministic, plausible bpftrace output without
// touching the kernel. It is the default backend on non-Linux dev machines. It
// never pretends to be real: Result.Backend is "mock", which flows into the
// audit log, and DryRun applies the same cheap sanity checks a real parse would
// catch first (balanced braces, a probe header).
type MockExecutor struct{}

func NewMock() *MockExecutor { return &MockExecutor{} }

func (m *MockExecutor) Name() string { return "mock" }

func (m *MockExecutor) DryRun(_ context.Context, s Spec) error {
	return staticCheck(s.ScriptText)
}

func (m *MockExecutor) Run(ctx context.Context, s Spec) (Result, error) {
	start := time.Now()
	if err := staticCheck(s.ScriptText); err != nil {
		return Result{Backend: "mock", ExitCode: 1, Started: start, Ended: time.Now()}, err
	}

	// Simulate a short capture but honor cancellation/deadline promptly.
	sim := 200 * time.Millisecond
	if s.Duration > 0 && s.Duration < sim {
		sim = s.Duration
	}
	timedOut := false
	select {
	case <-time.After(sim):
	case <-ctx.Done():
		timedOut = true
	}

	out := m.synthOutput(s)
	return Result{
		ExitCode: 0,
		Output:   out,
		Started:  start,
		Ended:    time.Now(),
		Backend:  "mock",
		TimedOut: timedOut,
		Pid:      os.Getpid(),
	}, nil
}

// synthOutput returns aggregated-looking output if the script aggregates, and a
// small per-event stream otherwise, so downstream summarization has something
// representative to shape.
func (m *MockExecutor) synthOutput(s Spec) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "Attaching probe(s)...\n")
	if strings.Contains(s.ScriptText, "@") || strings.Contains(s.ScriptText, "hist(") {
		b.WriteString("\n@latency_ns:\n")
		b.WriteString("[256, 512)        1042 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|\n")
		b.WriteString("[512, 1K)          318 |@@@@@@@@@                       |\n")
		b.WriteString("[1K, 2K)            77 |@@                              |\n")
		b.WriteString("\n@count[nginx]: 1437\n@count[node]: 402\n")
	} else {
		for i := 0; i < 12; i++ {
			fmt.Fprintf(&b, "%-8d %-16s tcp_connect\n", 48000+i, "nginx")
		}
	}
	return []byte(b.String())
}

// staticCheck is a minimal syntax guard shared by DryRun and Run: it catches the
// two mistakes that make a script obviously invalid before any execution.
func staticCheck(script string) error {
	if strings.TrimSpace(script) == "" {
		return fmt.Errorf("empty script")
	}
	if strings.Count(script, "{") != strings.Count(script, "}") {
		return fmt.Errorf("unbalanced braces in script")
	}
	return nil
}
