// Package catalog is the single source of truth for what probes are allowed,
// which attach points are high-frequency (and therefore require aggregation),
// and the duration bounds. The policy engine evaluates against this exact data
// and list_probe_catalog advertises this exact data, so what is advertised can
// never drift from what is enforced.
package catalog

// Category groups attach points for human/agent discovery.
type Category string

const (
	Network   Category = "network"
	Process   Category = "process"
	DiskIO    Category = "disk_io"
	Scheduler Category = "scheduler"
)

// AttachPoint is one whitelisted place a probe may attach.
type AttachPoint struct {
	Name          string   `json:"name"`
	Category      Category `json:"category"`
	HighFrequency bool     `json:"high_frequency"` // requires an aggregation, not raw per-event output
	Description   string   `json:"description"`
}

// Catalog is the whole allow-list plus the global limits policy enforces.
type Catalog struct {
	BundleVersion   string        `json:"bundle_version"`
	ProbeTypes      []string      `json:"probe_types"`      // allowed bpftrace probe kinds
	AttachPoints    []AttachPoint `json:"attach_points"`    // allowed attach points
	DefaultDuration int           `json:"default_duration"` // seconds, used when a spec omits one
	MaxDuration     int           `json:"max_duration"`     // seconds, hard cap enforced by policy
	MaxConcurrent   int           `json:"max_concurrent"`   // max simultaneously-running probes per host
}

// Default is the built-in catalog. In a later phase this loads from the host's
// actually-available tracepoints (Phase 4); the shape stays identical so policy
// and discovery don't change.
func Default() Catalog {
	return Catalog{
		BundleVersion:   "2026.07.01",
		ProbeTypes:      []string{"kprobe", "kretprobe", "tracepoint", "uprobe", "interval", "profile"},
		DefaultDuration: 30,
		MaxDuration:     300,
		MaxConcurrent:   4,
		AttachPoints: []AttachPoint{
			{"tcp_connect", Network, false, "outbound TCP connection attempts"},
			{"tcp_retransmit_skb", Network, false, "TCP retransmissions (latency/loss signal)"},
			{"sys_enter_openat", Process, true, "file opens — fires constantly, aggregate it"},
			{"sys_enter_read", Process, true, "read() entry — very high frequency"},
			{"sys_enter_write", Process, true, "write() entry — very high frequency"},
			{"sys_enter_execve", Process, false, "process execution (exec) — moderate rate"},
			{"block_rq_issue", DiskIO, false, "block I/O request issued to device"},
			{"block_rq_complete", DiskIO, true, "block I/O completion — high frequency under load"},
			{"sched_switch", Scheduler, true, "context switches — extremely high frequency"},
			{"sched_process_exec", Scheduler, false, "process exec at scheduler level"},
		},
	}
}

// Lookup returns the AttachPoint for a name, or ok=false if not whitelisted.
func (c Catalog) Lookup(name string) (AttachPoint, bool) {
	for _, ap := range c.AttachPoints {
		if ap.Name == name {
			return ap, true
		}
	}
	return AttachPoint{}, false
}

// AllowsProbeType reports whether a probe kind is on the allow-list.
func (c Catalog) AllowsProbeType(t string) bool {
	for _, pt := range c.ProbeTypes {
		if pt == t {
			return true
		}
	}
	return false
}

// IsHighFrequency reports whether an attach point requires aggregation.
func (c Catalog) IsHighFrequency(name string) bool {
	ap, ok := c.Lookup(name)
	return ok && ap.HighFrequency
}

// GroupByCategory returns attach points bucketed by category for discovery.
func (c Catalog) GroupByCategory() map[Category][]AttachPoint {
	out := map[Category][]AttachPoint{}
	for _, ap := range c.AttachPoints {
		out[ap.Category] = append(out[ap.Category], ap)
	}
	return out
}
