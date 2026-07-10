//go:build linux

package exec

import "os"

// Default selects the real bpftrace backend when the binary is present,
// otherwise falls back to the mock so the tool still runs (and says so).
func Default() Executor {
	bt := NewBpftrace()
	if _, err := os.Stat(bt.BinPath); err == nil {
		return bt
	}
	return NewMock()
}
