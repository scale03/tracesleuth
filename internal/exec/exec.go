// Package exec runs a validated bpftrace script and captures its result. The
// daemon depends only on the Executor interface, so the real kernel path
// (bpftrace under sudo, on Linux) and the deterministic mock (for development
// on non-Linux hosts and for tests) are interchangeable and neither the audit
// log nor the policy layer knows which one produced a result.
package exec

import (
	"context"
	"time"
)

// Spec is a probe ready to execute: it has already passed dry-run and policy.
type Spec struct {
	ProbeID    string
	ScriptText string
	Duration   time.Duration
}

// Result is what an execution produced.
type Result struct {
	ExitCode int
	Output   []byte
	Started  time.Time
	Ended    time.Time
	// Pid is the OS process id of the executed probe (the bpftrace/sudo pid for
	// the real backend), recorded in the probe_started audit event.
	Pid int
	// Backend names which executor produced this ("bpftrace" or "mock"). It is
	// recorded so the audit trail never implies a mock result was a real one.
	Backend string
	// TimedOut is true if the probe was stopped by its duration deadline rather
	// than exiting on its own (a normal, expected outcome for timed captures).
	TimedOut bool
}

// Executor runs a Spec and returns its Result. Implementations must respect the
// Spec.Duration as a hard deadline.
type Executor interface {
	Run(ctx context.Context, s Spec) (Result, error)
	// DryRun performs a parse/validation check without attaching to the kernel.
	DryRun(ctx context.Context, s Spec) error
	// Name identifies the backend for logging.
	Name() string
	// List enumerates the probes the host exposes, optionally narrowed by a
	// bpftrace probe glob (e.g. "tracepoint:*", "kprobe:tcp*"). An empty filter
	// lists everything. This is discovery — it attaches to nothing.
	List(ctx context.Context, filter string) ([]string, error)
}
