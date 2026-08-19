package env

import (
	"runtime"
	"testing"
)

// Capture must never fail, even with no bpftrace and no privilege: unknown
// fields come back empty rather than erroring.
func TestCaptureDegradesGracefully(t *testing.T) {
	e := Capture("/nonexistent/bpftrace", false)
	if e.Arch != runtime.GOARCH {
		t.Fatalf("arch should always be set, got %q", e.Arch)
	}
	if e.BpftraceVersion != "" || e.ProbeCount != 0 {
		t.Fatalf("a missing bpftrace should leave version/count zero, got %q / %d", e.BpftraceVersion, e.ProbeCount)
	}
}

func TestFirstLine(t *testing.T) {
	if got := firstLine("6.1.0-test\nignored\n"); got != "6.1.0-test" {
		t.Fatalf("want first line only, got %q", got)
	}
	if got := firstLine("  trimmed  "); got != "trimmed" {
		t.Fatalf("want trimmed, got %q", got)
	}
}

func TestUnquote(t *testing.T) {
	if got := unquote(`"Fedora Linux 40"`); got != "Fedora Linux 40" {
		t.Fatalf("want unquoted PRETTY_NAME, got %q", got)
	}
	if got := unquote("Bare Value"); got != "Bare Value" {
		t.Fatalf("want bare value unchanged, got %q", got)
	}
}
