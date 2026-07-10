// Package catalog is the single source of truth for what probes are allowed,
// which attach points are high-frequency (and therefore require aggregation),
// and the duration bounds. The policy engine evaluates against this exact data
// and list_probe_catalog advertises this exact data, so what is advertised can
// never drift from what is enforced.
package catalog

import (
	"encoding/json"
	"os"
)

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

// Catalog is the catalog + limits the policy reasons about. Under the
// default-allow posture (bundle 2026.07.02+) AttachPoints/ProbeTypes are the
// advertised, known-good set for discovery — NOT a hard allow-list. Enforcement
// is deny-list: DeniedAttachPoints/DeniedProbeTypes carve capability out, and the
// high-frequency flag plus the duration/concurrency limits constrain modality.
type Catalog struct {
	BundleVersion   string        `json:"bundle_version"`
	ProbeTypes      []string      `json:"probe_types"`    // advertised bpftrace probe kinds
	AttachPoints    []AttachPoint `json:"attach_points"`  // advertised attach points (discovery)
	DefaultDuration int           `json:"default_duration"` // seconds, used when a spec omits one
	MaxDuration     int           `json:"max_duration"`     // seconds, hard cap enforced by policy
	MaxConcurrent   int           `json:"max_concurrent"`   // max simultaneously-running probes per host

	// Deny-lists: explicit carve-outs from otherwise-full capability. Empty by
	// default (open). Edit these (via a TRACESLEUTH_CATALOG file) to forbid
	// specific attach points or probe types without recompiling.
	DeniedAttachPoints []string `json:"denied_attach_points,omitempty"`
	DeniedProbeTypes   []string `json:"denied_probe_types,omitempty"`
}

// Default is the built-in catalog. In a later phase this loads from the host's
// actually-available tracepoints (Phase 4); the shape stays identical so policy
// and discovery don't change.
func Default() Catalog {
	return Catalog{
		BundleVersion:   "2026.07.02",
		ProbeTypes:      []string{"kprobe", "kretprobe", "tracepoint", "uprobe", "interval", "profile"},
		DefaultDuration: 30,
		MaxDuration:     300,
		MaxConcurrent:   4,
		AttachPoints: []AttachPoint{
			{"tcp_connect", Network, false, "outbound TCP connection attempts"},
			{"tcp_retransmit_skb", Network, false, "TCP retransmissions (latency/loss signal)"},
			{"inet_csk_accept", Network, false, "inbound TCP connections accepted (server side) — kretprobe returns the new sock"},
			{"sys_enter_openat", Process, true, "file opens — fires constantly, aggregate it"},
			{"sys_enter_read", Process, true, "read() entry — very high frequency"},
			{"sys_enter_write", Process, true, "write() entry — very high frequency"},
			{"sys_enter_execve", Process, false, "process execution (exec) — moderate rate"},
			{"sched_process_exit", Process, false, "process exit (teardown) — complements execve for full lifecycle"},
			{"vfs_unlink", Process, false, "file deletions (unlink) — who removes files, and what path"},
			{"signal_generate", Process, false, "signals sent between processes (SIGKILL/SIGTERM/…) — explains process deaths"},
			{"block_rq_issue", DiskIO, false, "block I/O request issued to device"},
			{"block_rq_complete", DiskIO, true, "block I/O completion — high frequency under load"},
			{"sched_switch", Scheduler, true, "context switches — extremely high frequency"},
			{"sched_process_exec", Scheduler, false, "process exec at scheduler level"},
		},
	}
}

// Load reads a catalog from a JSON file — the runtime override that lets an
// operator change caps, the high-frequency set (via attach_points), or the
// deny-lists without recompiling. The file shape is this struct's JSON encoding.
func Load(path string) (Catalog, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return Catalog{}, err
	}
	var c Catalog
	if err := json.Unmarshal(b, &c); err != nil {
		return Catalog{}, err
	}
	return c, nil
}

// AsData renders the catalog as the data.catalog document the Rego policy reads.
// The high-frequency set is derived from the advertised attach points; the
// deny-lists and limits pass through. Slices are never nil so Rego membership
// checks against them are always well-defined.
func (c Catalog) AsData() map[string]any {
	hf := []string{}
	for _, ap := range c.AttachPoints {
		if ap.HighFrequency {
			hf = append(hf, ap.Name)
		}
	}
	denyAP := c.DeniedAttachPoints
	if denyAP == nil {
		denyAP = []string{}
	}
	denyPT := c.DeniedProbeTypes
	if denyPT == nil {
		denyPT = []string{}
	}
	return map[string]any{
		"high_frequency":       hf,
		"denied_attach_points": denyAP,
		"denied_probe_types":   denyPT,
		"default_duration":     c.DefaultDuration,
		"max_duration":         c.MaxDuration,
		"max_concurrent":       c.MaxConcurrent,
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
