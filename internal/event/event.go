// Package event defines the append-only JSONL audit contract and its hash chain.
//
// This is the source of truth for TraceSleuth: every meaningful thing that
// happens in an investigation is one line here. The SQLite index (package
// store) is a disposable projection rebuilt from these files. If you change a
// field here, you are changing the contract the whole system depends on.
package event

import (
	"time"
)

// Type is the discriminator for an audit line. Adding a new type is a contract
// change: the verifier, the store projection, and any reader must handle it.
type Type string

const (
	InvestigationOpened Type = "investigation_opened"
	HypothesisDeclared  Type = "hypothesis_declared"
	ProbeProposed       Type = "probe_proposed"
	PolicyDecision      Type = "policy_decision"
	ProbeStarted        Type = "probe_started"
	ProbeEnded          Type = "probe_ended"
	InvestigationClosed Type = "investigation_closed"
)

// Event is a single line in an investigation's JSONL log.
//
// All type-specific fields are omitempty so one struct can represent every
// event type while still round-tripping exactly (unmarshal then marshal yields
// identical bytes), which is what makes the hash chain verifiable. Fields whose
// zero value is meaningful (ExitCode==0 means success, DurationS==0 is a valid
// duration) are pointers so "absent" and "zero" stay distinguishable.
type Event struct {
	// Chain/envelope fields — present on every line.
	Seq             int    `json:"seq"`
	TS              string `json:"ts"`
	Event           Type   `json:"event"`
	InvestigationID string `json:"investigation_id"`
	PrevHash        string `json:"prev_hash"`
	Hash            string `json:"hash"`

	// investigation_opened
	AgentIdentity string   `json:"agent_identity,omitempty"`
	IdentityRoles []string `json:"identity_roles,omitempty"`
	Host          string   `json:"host,omitempty"`

	// hypothesis_declared
	Text string `json:"text,omitempty"`

	// probe_proposed
	ProbeID      string   `json:"probe_id,omitempty"`
	ScriptSHA256 string   `json:"script_sha256,omitempty"`
	ScriptText   string   `json:"script_text,omitempty"`
	ProbeTypes   []string `json:"probe_types,omitempty"`
	AttachPoints []string `json:"attach_points,omitempty"`
	DurationS    *int     `json:"duration_s,omitempty"`

	// policy_decision
	Decision            string   `json:"decision,omitempty"` // allow | deny | needs_approval
	PolicyBundleVersion string   `json:"policy_bundle_version,omitempty"`
	Reason              string   `json:"reason,omitempty"`
	Reasons             []string `json:"reasons,omitempty"`

	// probe_started
	Pid *int `json:"pid,omitempty"`

	// probe_ended
	ExitCode     *int   `json:"exit_code,omitempty"`
	OutputSHA256 string `json:"output_sha256,omitempty"`
	OutputPath   string `json:"output_path,omitempty"`

	// investigation_closed
	Conclusion string `json:"conclusion,omitempty"`
}

// Now returns an RFC3339 UTC timestamp string, the format used in the TS field.
func Now() string {
	return time.Now().UTC().Format(time.RFC3339)
}

// IntPtr is a small helper for populating the pointer-valued fields.
func IntPtr(v int) *int { return &v }
