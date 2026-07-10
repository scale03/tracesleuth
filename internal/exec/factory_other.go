//go:build !linux

package exec

// Default is the mock backend on non-Linux hosts: bpftrace needs a Linux
// kernel, so there is nothing real to run here. Results are marked "mock" in the
// audit log so this is never mistaken for a genuine kernel capture.
func Default() Executor { return NewMock() }
