// Package service is the daemon core: it ties the audit log, policy engine,
// executor, and SQLite index into the one flow that matters —
// hypothesis → probe → policy decision → result — and guarantees every step is
// written to the append-only log before (or as) it happens. Transports (local
// CLI now, Teleport later) and executors (mock/bpftrace) plug in around it; this
// layer never knows which.
package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"tracesleuth/internal/catalog"
	"tracesleuth/internal/cost"
	"tracesleuth/internal/event"
	"tracesleuth/internal/exec"
	"tracesleuth/internal/output"
	"tracesleuth/internal/policy"
	"tracesleuth/internal/store"
)

// Identity is who is driving an investigation. In Phase 1 it comes from a CLI
// flag; in Phase 2 the same struct is populated from a Teleport certificate by
// an IdentityResolver, and nothing downstream changes.
type Identity struct {
	Name  string
	Roles []string
}

// Config locates the daemon's on-disk state.
type Config struct {
	DataDir  string // holds logs/, outputs/, index.db
	Host     string // this host's name, recorded on every investigation
	Executor exec.Executor
	Catalog  catalog.Catalog
	// Policy is the OPA decision engine. If nil, New builds one from the embedded
	// policy and Catalog.AsData() — the built-in default-allow + deny-list posture.
	Policy *policy.Engine
}

// Service is safe for sequential CLI use; concurrent investigations get their
// own append log so their chains never interleave.
type Service struct {
	cfg     Config
	logsDir string
	outDir  string
	store   *store.Store
}

// PolicyFromEnv loads the catalog (TRACESLEUTH_CATALOG, JSON) and policy module
// (TRACESLEUTH_POLICY, Rego) from disk, each falling back to the built-in
// compiled default, and returns the catalog plus a compiled engine. Both the MCP
// server and tracectl call this so they enforce byte-for-byte the same policy —
// changing the files (no recompile) affects every entry point at once.
func PolicyFromEnv() (catalog.Catalog, *policy.Engine, error) {
	cat := catalog.Default()
	if p := os.Getenv("TRACESLEUTH_CATALOG"); p != "" {
		loaded, err := catalog.Load(p)
		if err != nil {
			return cat, nil, fmt.Errorf("load catalog %s: %w", p, err)
		}
		cat = loaded
	}
	module := "" // empty => embedded default policy
	if p := os.Getenv("TRACESLEUTH_POLICY"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return cat, nil, fmt.Errorf("load policy %s: %w", p, err)
		}
		module = string(b)
	}
	eng, err := policy.NewEngine(context.Background(), module, cat.AsData(), cat.BundleVersion)
	if err != nil {
		return cat, nil, fmt.Errorf("policy engine: %w", err)
	}
	return cat, eng, nil
}

// New opens the index and ensures the directory layout exists.
func New(cfg Config) (*Service, error) {
	logsDir := filepath.Join(cfg.DataDir, "logs")
	outDir := filepath.Join(cfg.DataDir, "outputs")
	for _, d := range []string{logsDir, outDir} {
		if err := os.MkdirAll(d, 0o750); err != nil {
			return nil, err
		}
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "index.db"))
	if err != nil {
		return nil, err
	}
	if cfg.Executor == nil {
		// TRACESLEUTH_EXECUTOR=mock forces the mock backend even on Linux — used
		// for dev/demo before root/bpftrace is wired up. Any other value (or
		// unset) uses the platform default (real bpftrace on Linux).
		if os.Getenv("TRACESLEUTH_EXECUTOR") == "mock" {
			cfg.Executor = exec.NewMock()
		} else {
			cfg.Executor = exec.Default()
		}
	}
	if cfg.Catalog.BundleVersion == "" {
		cfg.Catalog = catalog.Default()
	}
	if cfg.Policy == nil {
		eng, err := policy.NewEngine(context.Background(), "", cfg.Catalog.AsData(), cfg.Catalog.BundleVersion)
		if err != nil {
			return nil, fmt.Errorf("build policy engine: %w", err)
		}
		cfg.Policy = eng
	}
	return &Service{cfg: cfg, logsDir: logsDir, outDir: outDir, store: st}, nil
}

func (s *Service) Close() error { return s.store.Close() }
func (s *Service) Store() *store.Store { return s.store }
func (s *Service) Catalog() catalog.Catalog { return s.cfg.Catalog }

// openLog returns the append log for an investigation, appends the event, and
// projects it into the index — the two writes that must always happen together.
func (s *Service) record(id string, e event.Event) (event.Event, error) {
	lg, err := event.OpenLog(s.logsDir, id)
	if err != nil {
		return event.Event{}, err
	}
	defer lg.Close()
	e.InvestigationID = id
	written, err := lg.Append(e)
	if err != nil {
		return event.Event{}, err
	}
	if err := s.store.Apply(written); err != nil {
		return event.Event{}, err
	}
	return written, nil
}

// Open starts a new investigation and returns its id.
func (s *Service) Open(id Identity) (string, error) {
	invID := "inv_" + randID(4)
	_, err := s.record(invID, event.Event{
		Event:         event.InvestigationOpened,
		AgentIdentity: id.Name,
		IdentityRoles: id.Roles,
		Host:          s.cfg.Host,
	})
	return invID, err
}

// Hypothesis records what the investigation is testing.
func (s *Service) Hypothesis(invID, text string) error {
	_, err := s.record(invID, event.Event{Event: event.HypothesisDeclared, Text: text})
	return err
}

// Close records the conclusion and marks the investigation closed.
func (s *Service) Close_(invID, conclusion string) error {
	_, err := s.record(invID, event.Event{Event: event.InvestigationClosed, Conclusion: conclusion})
	return err
}

// ProbeRequest is a probe an agent wants to run within an investigation.
type ProbeRequest struct {
	ProbeTypes   []string
	AttachPoints []string
	ScriptText   string
	DurationS    int
	FilterPID    bool
	FilterComm   bool
}

// ProbeReport is the result surface — designed for the Phase 8 response shape:
// status line, script, decision, in that order, legible even if truncated.
type ProbeReport struct {
	InvestigationID string
	ProbeID         string
	ScriptText      string
	Decision        string   // allow | deny
	Reasons         []string // actionable, from policy
	Ran             bool
	Backend         string
	Pid             int
	StartedAt       string
	ExitCode        int
	TimedOut        bool
	Summary         output.Summary
	OutputPath      string
}

// RunProbe executes the full per-probe pipeline: propose → dry-run → policy →
// (if allowed) run → capture. Every stage is logged, including denials. A denied
// probe returns a report with the actionable reasons and Ran=false; nothing
// touches the kernel.
func (s *Service) RunProbe(ctx context.Context, invID string, req ProbeRequest) (ProbeReport, error) {
	if req.DurationS == 0 {
		req.DurationS = s.cfg.Catalog.DefaultDuration
	}
	probeID := "p_" + randID(3)
	rep := ProbeReport{InvestigationID: invID, ProbeID: probeID, ScriptText: req.ScriptText}

	// 1. probe_proposed — the exact script, stored inline.
	if _, err := s.record(invID, event.Event{
		Event:        event.ProbeProposed,
		ProbeID:      probeID,
		ScriptSHA256: event.SHA256Hex([]byte(req.ScriptText)),
		ScriptText:   req.ScriptText,
		ProbeTypes:   req.ProbeTypes,
		AttachPoints: req.AttachPoints,
		DurationS:    event.IntPtr(req.DurationS),
	}); err != nil {
		return rep, err
	}

	spec := exec.Spec{ProbeID: probeID, ScriptText: req.ScriptText, Duration: time.Duration(req.DurationS) * time.Second}

	// 2. dry-run (cheap parse check) before policy, per the plan's ordering.
	if err := s.cfg.Executor.DryRun(ctx, spec); err != nil {
		reason := fmt.Sprintf("script failed validation (%s): %v", s.cfg.Executor.Name(), err)
		if _, e := s.recordDecision(invID, probeID, false, []string{reason}); e != nil {
			return rep, e
		}
		rep.Decision, rep.Reasons = "deny", []string{reason}
		return rep, nil
	}

	// 3. policy decision, evaluated against live investigation/host context.
	in := policy.Input{
		Action: policy.Action{
			ProbeTypes:   req.ProbeTypes,
			AttachPoints: req.AttachPoints,
			ScriptText:   req.ScriptText,
			DurationS:    req.DurationS,
			Filters:      policy.Filters{PID: req.FilterPID, Comm: req.FilterComm},
		},
		Context: policy.Context{
			ProbeCount:    s.priorProbeCount(invID, probeID),
			RunningOnHost: s.runningOnHost(),
		},
	}
	dec, err := s.cfg.Policy.Evaluate(ctx, in)
	if err != nil {
		// Evaluation failure denies (fail closed) and is recorded like any denial.
		reason := fmt.Sprintf("policy evaluation error: %v", err)
		if _, e := s.recordDecision(invID, probeID, false, []string{reason}); e != nil {
			return rep, e
		}
		rep.Decision, rep.Reasons = "deny", []string{reason}
		return rep, nil
	}
	if _, err := s.recordDecision(invID, probeID, dec.Allow, dec.Reasons); err != nil {
		return rep, err
	}
	rep.Decision, rep.Reasons = dec.Verdict(), dec.Reasons
	if !dec.Allow {
		return rep, nil // denied: nothing runs
	}

	// 4. execute.
	res, runErr := s.cfg.Executor.Run(ctx, spec)

	// 5. probe_started (recorded with the real start time + pid) then probe_ended.
	if _, err := s.record(invID, event.Event{
		Event: event.ProbeStarted, ProbeID: probeID, TS: res.Started.UTC().Format(time.RFC3339), Pid: event.IntPtr(res.Pid),
	}); err != nil {
		return rep, err
	}

	outPath := filepath.Join("outputs", invID, probeID+".log")
	absOut := filepath.Join(s.cfg.DataDir, outPath)
	if err := os.MkdirAll(filepath.Dir(absOut), 0o750); err != nil {
		return rep, err
	}
	if err := os.WriteFile(absOut, res.Output, 0o640); err != nil {
		return rep, err
	}

	if _, err := s.record(invID, event.Event{
		Event: event.ProbeEnded, ProbeID: probeID,
		TS:           res.Ended.UTC().Format(time.RFC3339),
		ExitCode:     event.IntPtr(res.ExitCode),
		OutputSHA256: event.SHA256Hex(res.Output),
		OutputPath:   outPath,
	}); err != nil {
		return rep, err
	}

	rep.Ran = true
	rep.Backend = res.Backend
	rep.Pid = res.Pid
	rep.StartedAt = res.Started.Format("15:04:05")
	rep.ExitCode = res.ExitCode
	rep.TimedOut = res.TimedOut
	rep.Summary = output.Summarize(res.Output)
	rep.OutputPath = outPath
	return rep, runErr
}

// PreviewReport is what preview_probe returns: the same decision run_probe would
// reach, plus a cost estimate, without running anything or writing to the chain.
type PreviewReport struct {
	InvestigationID string
	ScriptText      string
	Decision        string // allow | deny
	Reasons         []string
	Estimate        cost.Estimate
}

// PreviewProbe runs dry-run + policy and estimates cost, but never executes and
// never records — it exists so a human can see and approve exactly what would
// run first. invID is optional: when set, the decision reflects that
// investigation's context (the first-probe rule keys off its prior probe count);
// when empty, the probe is evaluated as if it were the first in a new one.
func (s *Service) PreviewProbe(ctx context.Context, invID string, req ProbeRequest) (PreviewReport, error) {
	if req.DurationS == 0 {
		req.DurationS = s.cfg.Catalog.DefaultDuration
	}
	rep := PreviewReport{
		InvestigationID: invID,
		ScriptText:      req.ScriptText,
		Estimate:        cost.Of(s.cfg.Catalog, req.AttachPoints, req.ScriptText, req.FilterPID, req.FilterComm),
	}

	spec := exec.Spec{ProbeID: "preview", ScriptText: req.ScriptText, Duration: time.Duration(req.DurationS) * time.Second}
	if err := s.cfg.Executor.DryRun(ctx, spec); err != nil {
		rep.Decision = "deny"
		rep.Reasons = []string{fmt.Sprintf("script failed validation (%s): %v", s.cfg.Executor.Name(), err)}
		return rep, nil
	}

	in := policy.Input{
		Action: policy.Action{
			ProbeTypes:   req.ProbeTypes,
			AttachPoints: req.AttachPoints,
			ScriptText:   req.ScriptText,
			DurationS:    req.DurationS,
			Filters:      policy.Filters{PID: req.FilterPID, Comm: req.FilterComm},
		},
		Context: policy.Context{
			ProbeCount:    s.priorProbeCount(invID, ""),
			RunningOnHost: s.runningOnHost(),
		},
	}
	dec, err := s.cfg.Policy.Evaluate(ctx, in)
	if err != nil {
		rep.Decision = "deny"
		rep.Reasons = []string{fmt.Sprintf("policy evaluation error: %v", err)}
		return rep, nil
	}
	rep.Decision, rep.Reasons = dec.Verdict(), dec.Reasons
	return rep, nil
}

func (s *Service) recordDecision(invID, probeID string, allow bool, reasons []string) (event.Event, error) {
	decision := "deny"
	if allow {
		decision = "allow"
	}
	reason := "allowed by policy"
	if !allow && len(reasons) > 0 {
		reason = reasons[0]
	} else if allow {
		reason = "within allow-list, duration, aggregation, and scoping rules"
	}
	return s.record(invID, event.Event{
		Event:               event.PolicyDecision,
		ProbeID:             probeID,
		Decision:            decision,
		PolicyBundleVersion: s.cfg.Catalog.BundleVersion,
		Reason:              reason,
		Reasons:             reasons,
	})
}

// priorProbeCount counts probes already proposed in this investigation, other
// than the one being evaluated — the "coarse-then-narrow" first-probe rule keys
// off this being zero.
func (s *Service) priorProbeCount(invID, exceptProbeID string) int {
	inv, ok, err := s.store.Get(invID)
	if err != nil || !ok {
		return 0
	}
	n := 0
	for _, p := range inv.Probes {
		if p.ID != exceptProbeID {
			n++
		}
	}
	return n
}

// runningOnHost counts probes started but not yet ended on this host, feeding the
// concurrency cap. Synchronous execution keeps this near zero, but the rule is
// enforced regardless so async baselines (Phase 7) inherit it for free.
func (s *Service) runningOnHost() int {
	invs, err := s.store.List(store.ListFilter{Host: s.cfg.Host})
	if err != nil {
		return 0
	}
	n := 0
	for _, iv := range invs {
		full, ok, _ := s.store.Get(iv.ID)
		if !ok {
			continue
		}
		for _, p := range full.Probes {
			if p.StartedAt != "" && p.EndedAt == "" {
				n++
			}
		}
	}
	return n
}

// Reindex rebuilds the SQLite projection from the JSONL source of truth.
func (s *Service) Reindex() (int, error) {
	evs, err := event.ReadDir(s.logsDir)
	if err != nil {
		return 0, err
	}
	if err := s.store.Rebuild(evs); err != nil {
		return 0, err
	}
	return len(evs), nil
}

// LogsDir exposes the JSONL directory for the verifier tool.
func (s *Service) LogsDir() string { return s.logsDir }

func randID(nbytes int) string {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is fatal-adjacent; fall back to a time seed.
		return hex.EncodeToString([]byte(time.Now().Format("150405")))[:nbytes*2]
	}
	return hex.EncodeToString(b)
}
