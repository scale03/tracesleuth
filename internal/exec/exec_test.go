package exec

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestStaticCheck(t *testing.T) {
	cases := []struct {
		name    string
		script  string
		wantErr string
	}{
		{"empty", "   \n\t ", "empty script"},
		{"unbalanced", "kprobe:tcp_connect { @=count();", "unbalanced braces"},
		{"balanced", "kprobe:tcp_connect { @=count(); }", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := staticCheck(c.script)
			switch {
			case c.wantErr == "" && err != nil:
				t.Fatalf("want ok, got %v", err)
			case c.wantErr != "" && (err == nil || !strings.Contains(err.Error(), c.wantErr)):
				t.Fatalf("want error containing %q, got %v", c.wantErr, err)
			}
		})
	}
}

func TestMockRunSucceeds(t *testing.T) {
	m := NewMock()
	res, err := m.Run(context.Background(), Spec{ScriptText: "kprobe:tcp_connect { @=count(); }", Duration: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if res.Backend != "mock" {
		t.Fatalf("backend must be mock, got %q", res.Backend)
	}
	if res.ExitCode != 0 || res.Pid == 0 || res.Ended.Before(res.Started) {
		t.Fatalf("implausible result: %+v", res)
	}
}

// DryRun and Run share staticCheck, so an invalid script is rejected on both
// paths and never reports a clean exit.
func TestMockRejectsInvalidScript(t *testing.T) {
	m := NewMock()
	spec := Spec{ScriptText: "kprobe:x {"}
	if err := m.DryRun(context.Background(), spec); err == nil {
		t.Fatal("DryRun accepted unbalanced script")
	}
	res, err := m.Run(context.Background(), spec)
	if err == nil {
		t.Fatal("Run accepted unbalanced script")
	}
	if res.ExitCode == 0 {
		t.Fatalf("failed run must not report exit 0: %+v", res)
	}
}

// The synthetic output shape follows the script: aggregating scripts get a
// histogram/map block so downstream summarization has something to shape.
func TestMockOutputShapeFollowsScript(t *testing.T) {
	m := NewMock()
	agg, _ := m.Run(context.Background(), Spec{ScriptText: "kprobe:tcp_connect { @latency = hist(x); }", Duration: time.Second})
	if !strings.Contains(string(agg.Output), "@latency_ns") {
		t.Fatalf("aggregating script should yield a map block:\n%s", agg.Output)
	}
	raw, _ := m.Run(context.Background(), Spec{ScriptText: "kprobe:tcp_connect { printf(\"hi\"); }", Duration: time.Second})
	if strings.Contains(string(raw.Output), "@latency_ns") {
		t.Fatalf("non-aggregating script should yield a per-event stream:\n%s", raw.Output)
	}
}

// A cancelled context stops the simulated capture promptly and marks it timed
// out, mirroring the real deadline path.
func TestMockHonorsContextCancellation(t *testing.T) {
	m := NewMock()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	res, err := m.Run(ctx, Spec{ScriptText: "kprobe:tcp_connect { @=count(); }", Duration: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if !res.TimedOut {
		t.Fatal("cancelled run should be marked TimedOut")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("cancellation was not prompt: took %s", time.Since(start))
	}
}
