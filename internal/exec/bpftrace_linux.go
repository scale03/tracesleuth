//go:build linux

package exec

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"syscall"
	"time"
)

// Bpftrace runs real eBPF programs via the bpftrace binary. It requires root,
// which the daemon obtains through a NOPASSWD sudo rule scoped to exactly the
// bpftrace path (see /etc/sudoers.d/tracesleuth). Nothing else in the system
// gets elevated privilege.
type Bpftrace struct {
	// BinPath is the bpftrace executable; must match the sudoers rule exactly.
	BinPath string
	// UseSudo wraps the call in `sudo -n` (non-interactive). Set false only if
	// the daemon itself already runs as root.
	UseSudo bool
	// GracePeriod is how long to let bpftrace flush its maps after the deadline
	// SIGINT before escalating to SIGKILL.
	GracePeriod time.Duration
}

// NewBpftrace returns a Bpftrace executor with sensible defaults.
func NewBpftrace() *Bpftrace {
	return &Bpftrace{BinPath: "/usr/bin/bpftrace", UseSudo: true, GracePeriod: 3 * time.Second}
}

func (b *Bpftrace) Name() string { return "bpftrace" }

func (b *Bpftrace) argv(extra ...string) (string, []string) {
	args := append([]string{}, extra...)
	if b.UseSudo {
		return "sudo", append([]string{"-n", b.BinPath}, args...)
	}
	return b.BinPath, args
}

// DryRun validates the script with bpftrace's own parser (--dry-run / -d) so
// syntax errors are caught cheaply before policy and before touching the kernel.
func (b *Bpftrace) DryRun(ctx context.Context, s Spec) error {
	if err := staticCheck(s.ScriptText); err != nil {
		return err
	}
	f, err := writeScript(s)
	if err != nil {
		return err
	}
	defer os.Remove(f)

	// bpftrace parses and type-checks with --dry-run without attaching probes.
	name, args := b.argv("--dry-run", f)
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("bpftrace dry-run failed: %v: %s", err, stderr.String())
	}
	return nil
}

// List enumerates the host's probes via `bpftrace -l`, narrowed by a probe glob.
// Listing reads the kernel's tracing metadata (and needs the same privilege as a
// run), so it goes through the same sudo path; it attaches to nothing. Results
// are sorted for stable pagination.
func (b *Bpftrace) List(ctx context.Context, filter string) ([]string, error) {
	if filter == "" {
		filter = "*"
	}
	name, args := b.argv("-l", filter)
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("bpftrace -l failed: %v: %s", err, errb.String())
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	probes := lines[:0]
	for _, ln := range lines {
		if ln = strings.TrimSpace(ln); ln != "" {
			probes = append(probes, ln)
		}
	}
	sort.Strings(probes)
	return probes, nil
}

// Run executes the script and returns its captured output. The Spec.Duration is
// enforced by us, not left to the script: at the deadline we SIGINT bpftrace so
// it prints its aggregations and exits cleanly, escalating to SIGKILL only if it
// ignores the interrupt past GracePeriod.
func (b *Bpftrace) Run(ctx context.Context, s Spec) (Result, error) {
	start := time.Now()
	f, err := writeScript(s)
	if err != nil {
		return Result{Backend: "bpftrace", Started: start, Ended: time.Now()}, err
	}
	defer os.Remove(f)

	name, args := b.argv(f)
	cmd := exec.Command(name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	// Own process group so we can signal bpftrace even under sudo.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return Result{Backend: "bpftrace", Started: start, Ended: time.Now()}, err
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	deadline := time.NewTimer(s.Duration)
	defer deadline.Stop()

	timedOut := false
	select {
	case err = <-done:
		// bpftrace exited on its own before the deadline.
	case <-ctx.Done():
		timedOut = true
		b.signalAndWait(cmd, done)
		err = nil
	case <-deadline.C:
		timedOut = true
		b.signalAndWait(cmd, done)
		err = nil
	}

	exitCode := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			return Result{Backend: "bpftrace", Output: out.Bytes(), Started: start, Ended: time.Now()}, err
		}
	}
	pid := 0
	if cmd.Process != nil {
		pid = cmd.Process.Pid
	}
	return Result{
		ExitCode: exitCode,
		Output:   out.Bytes(),
		Started:  start,
		Ended:    time.Now(),
		Backend:  "bpftrace",
		TimedOut: timedOut,
		Pid:      pid,
	}, nil
}

// signalAndWait sends SIGINT (via sudo, so it reaches the real bpftrace), lets
// it flush its maps, then SIGKILLs the group if it overstays GracePeriod.
func (b *Bpftrace) signalAndWait(cmd *exec.Cmd, done chan error) {
	// Under sudo, signalling the sudo pid does not reach bpftrace; signal the
	// whole process group instead.
	pgid := cmd.Process.Pid
	_ = syscall.Kill(-pgid, syscall.SIGINT)

	grace := b.GracePeriod
	if grace <= 0 {
		grace = 3 * time.Second
	}
	select {
	case <-done:
	case <-time.After(grace):
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
		<-done
	}
}

func writeScript(s Spec) (string, error) {
	f, err := os.CreateTemp("", "tracesleuth-*.bt")
	if err != nil {
		return "", err
	}
	if _, err := f.WriteString(s.ScriptText); err != nil {
		f.Close()
		os.Remove(f.Name())
		return "", err
	}
	if err := f.Close(); err != nil {
		os.Remove(f.Name())
		return "", err
	}
	return f.Name(), nil
}
