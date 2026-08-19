// Package env captures the host context an investigation runs on — kernel,
// distro, arch, bpftrace version, BTF availability, and a probe count. It is
// best-effort by design: every field degrades to empty rather than failing, so
// capturing the environment can never block opening an investigation. On a
// non-Linux dev host most fields are simply blank.
package env

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"tracesleuth/internal/event"
)

// probeCountTimeout bounds the one potentially-slow call (listing every probe),
// so a busy or misconfigured host can't stall an open.
const probeCountTimeout = 3 * time.Second

// Capture inspects the host and returns what it can determine. bpftracePath is
// the binary to interrogate for the version and probe count; if it is empty or
// absent, those two fields stay zero.
func Capture(bpftracePath string, useSudo bool) event.Environment {
	e := event.Environment{
		Arch:   runtime.GOARCH,
		Kernel: firstLine(readFile("/proc/sys/kernel/osrelease")),
		Distro: osReleasePretty(),
		BTF:    fileExists("/sys/kernel/btf/vmlinux"),
	}
	if bpftracePath == "" {
		if p, err := exec.LookPath("bpftrace"); err == nil {
			bpftracePath = p
		}
	}
	if bpftracePath != "" && fileExists(bpftracePath) {
		e.BpftraceVersion = bpftraceVersion(bpftracePath)
		e.ProbeCount = probeCount(bpftracePath, useSudo)
	}
	return e
}

func bpftraceVersion(bin string) string {
	out, err := exec.Command(bin, "--version").Output()
	if err != nil {
		return ""
	}
	// "bpftrace v0.24.2" — keep the version token if present, else the line.
	fields := strings.Fields(firstLine(string(out)))
	if len(fields) >= 2 {
		return strings.TrimPrefix(fields[len(fields)-1], "v")
	}
	return firstLine(string(out))
}

// probeCount lists every attach point bpftrace can see and counts them. Listing
// generally needs root, so it runs under sudo when the executor does; on failure
// (no privilege, timeout) it returns 0 and the field is simply omitted. The
// accurate, paginated listing is M4's job — this is a coarse headline number.
func probeCount(bin string, useSudo bool) int {
	ctx, cancel := context.WithTimeout(context.Background(), probeCountTimeout)
	defer cancel()
	name, args := bin, []string{"-l"}
	if useSudo {
		name, args = "sudo", []string{"-n", bin, "-l"}
	}
	out, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return 0
	}
	n := 0
	sc := bufio.NewScanner(strings.NewReader(string(out)))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			n++
		}
	}
	return n
}

func osReleasePretty() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if v, ok := strings.CutPrefix(line, "PRETTY_NAME="); ok {
			return unquote(v)
		}
	}
	return ""
}

func readFile(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(b)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func unquote(s string) string {
	if u, err := strconv.Unquote(strings.TrimSpace(s)); err == nil {
		return u
	}
	return strings.Trim(strings.TrimSpace(s), `"`)
}
