package store

import (
	"testing"

	"tracesleuth/internal/event"
)

func open(t *testing.T) *Store {
	t.Helper()
	s, err := Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// fullChain is the event sequence a closed, run-once investigation produces, in
// the order the service writes them.
func fullChain(inv, probe string) []event.Event {
	return []event.Event{
		{Event: event.InvestigationOpened, InvestigationID: inv, AgentIdentity: "bot:x", Host: "h1", TS: "2026-08-18T10:00:00Z"},
		{Event: event.HypothesisDeclared, InvestigationID: inv, Text: "latency spike on tcp_connect"},
		{Event: event.ProbeProposed, InvestigationID: inv, ProbeID: probe, ScriptSHA256: "abc", ScriptText: "kprobe:tcp_connect { @=count(); }",
			ProbeTypes: []string{"kprobe"}, AttachPoints: []string{"tcp_connect"}, DurationS: event.IntPtr(30)},
		{Event: event.PolicyDecision, InvestigationID: inv, ProbeID: probe, Decision: "allow", PolicyBundleVersion: "2026.07.02"},
		{Event: event.ProbeStarted, InvestigationID: inv, ProbeID: probe, TS: "2026-08-18T10:00:05Z"},
		{Event: event.ProbeEnded, InvestigationID: inv, ProbeID: probe, TS: "2026-08-18T10:00:35Z",
			ExitCode: event.IntPtr(0), OutputSHA256: "def", OutputPath: "outputs/" + inv + "/" + probe + ".log"},
		{Event: event.InvestigationClosed, InvestigationID: inv, TS: "2026-08-18T10:00:36Z", Conclusion: "confirmed"},
	}
}

func applyAll(t *testing.T, s *Store, evs []event.Event) {
	t.Helper()
	for _, e := range evs {
		if err := s.Apply(e); err != nil {
			t.Fatalf("apply %s: %v", e.Event, err)
		}
	}
}

func TestApplyFoldsWholeChain(t *testing.T) {
	s := open(t)
	applyAll(t, s, fullChain("inv_1", "p_1"))

	inv, ok, err := s.Get("inv_1")
	if err != nil || !ok {
		t.Fatalf("get: ok=%v err=%v", ok, err)
	}
	if inv.Status != "closed" || inv.AgentIdentity != "bot:x" || inv.Host != "h1" {
		t.Fatalf("envelope not projected: %+v", inv)
	}
	if inv.Hypothesis == "" || inv.Conclusion != "confirmed" || inv.ClosedAt == "" {
		t.Fatalf("hypothesis/conclusion/closed_at missing: %+v", inv)
	}
	if len(inv.Probes) != 1 {
		t.Fatalf("expected 1 probe, got %d", len(inv.Probes))
	}
	p := inv.Probes[0]
	if p.PolicyDecision != "allow" || p.PolicyBundle != "2026.07.02" {
		t.Fatalf("decision not projected onto probe: %+v", p)
	}
	if !p.ExitCode.Valid || p.ExitCode.Int64 != 0 || p.OutputSHA256 != "def" || p.StartedAt == "" || p.EndedAt == "" {
		t.Fatalf("probe end fields missing: %+v", p)
	}
	if !p.DurationS.Valid || p.DurationS.Int64 != 30 {
		t.Fatalf("duration not projected: %+v", p.DurationS)
	}
}

func TestGetMissingIsNotAnError(t *testing.T) {
	s := open(t)
	_, ok, err := s.Get("nope")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for unknown id")
	}
}

// Apply must be idempotent: replaying the same events (as Rebuild does, or as a
// crash-and-recover would) converges to the same rows rather than duplicating.
func TestApplyIsIdempotent(t *testing.T) {
	s := open(t)
	chain := fullChain("inv_1", "p_1")
	applyAll(t, s, chain)
	applyAll(t, s, chain)

	inv, _, _ := s.Get("inv_1")
	if len(inv.Probes) != 1 {
		t.Fatalf("replay duplicated probes: got %d", len(inv.Probes))
	}
	if inv.Conclusion != "confirmed" || inv.Status != "closed" {
		t.Fatalf("replay lost terminal state: %+v", inv)
	}
}

// Rebuild is the recovery path the design hinges on: wipe the projection, replay
// the log, and land on identical state.
func TestRebuildReproducesState(t *testing.T) {
	s := open(t)
	chain := fullChain("inv_1", "p_1")
	applyAll(t, s, chain)
	before, _, _ := s.Get("inv_1")

	if err := s.Rebuild(chain); err != nil {
		t.Fatal(err)
	}
	after, ok, _ := s.Get("inv_1")
	if !ok {
		t.Fatal("investigation vanished after rebuild")
	}
	if before.Status != after.Status || before.Hypothesis != after.Hypothesis ||
		before.Conclusion != after.Conclusion || len(before.Probes) != len(after.Probes) {
		t.Fatalf("rebuild changed state:\n before=%+v\n after=%+v", before, after)
	}
}

func TestResetClearsRows(t *testing.T) {
	s := open(t)
	applyAll(t, s, fullChain("inv_1", "p_1"))
	if err := s.Reset(); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.Get("inv_1"); ok {
		t.Fatal("Reset left investigation rows behind")
	}
	list, _ := s.List(ListFilter{})
	if len(list) != 0 {
		t.Fatalf("Reset left %d rows", len(list))
	}
}

func TestListFilters(t *testing.T) {
	s := open(t)
	// Two hosts, mixed open/closed, different open times.
	s.Apply(event.Event{Event: event.InvestigationOpened, InvestigationID: "a", AgentIdentity: "x", Host: "h1", TS: "2026-08-01T00:00:00Z"})
	s.Apply(event.Event{Event: event.InvestigationOpened, InvestigationID: "b", AgentIdentity: "x", Host: "h1", TS: "2026-08-10T00:00:00Z"})
	s.Apply(event.Event{Event: event.InvestigationClosed, InvestigationID: "b", TS: "2026-08-10T01:00:00Z", Conclusion: "done"})
	s.Apply(event.Event{Event: event.InvestigationOpened, InvestigationID: "c", AgentIdentity: "x", Host: "h2", TS: "2026-08-15T00:00:00Z"})

	ids := func(f ListFilter) []string {
		t.Helper()
		rows, err := s.List(f)
		if err != nil {
			t.Fatal(err)
		}
		out := make([]string, len(rows))
		for i, r := range rows {
			out[i] = r.ID
		}
		return out
	}

	if got := ids(ListFilter{Host: "h1"}); len(got) != 2 {
		t.Fatalf("host filter: want 2, got %v", got)
	}
	if got := ids(ListFilter{Status: "closed"}); len(got) != 1 || got[0] != "b" {
		t.Fatalf("status filter: want [b], got %v", got)
	}
	if got := ids(ListFilter{Since: "2026-08-12T00:00:00Z"}); len(got) != 1 || got[0] != "c" {
		t.Fatalf("since filter: want [c], got %v", got)
	}
	if got := ids(ListFilter{Limit: 1}); len(got) != 1 {
		t.Fatalf("limit: want 1, got %v", got)
	}
	// Default order is opened_at DESC: newest (c) first.
	if got := ids(ListFilter{}); got[0] != "c" || got[2] != "a" {
		t.Fatalf("expected opened_at DESC order, got %v", got)
	}
}

// List returns summaries without probes; Get is what carries the probe rows.
func TestListOmitsProbes(t *testing.T) {
	s := open(t)
	applyAll(t, s, fullChain("inv_1", "p_1"))
	rows, _ := s.List(ListFilter{})
	if len(rows) != 1 || rows[0].Probes != nil {
		t.Fatalf("List should not carry probes, got %+v", rows)
	}
}

// A decision or start arriving before the probe row exists must not crash the
// projection — the UPDATE simply matches nothing until probe_proposed lands.
func TestOutOfOrderUpdatesAreHarmless(t *testing.T) {
	s := open(t)
	if err := s.Apply(event.Event{Event: event.PolicyDecision, InvestigationID: "inv_1", ProbeID: "p_1", Decision: "allow"}); err != nil {
		t.Fatalf("orphan decision errored: %v", err)
	}
	inv, _, _ := s.Get("inv_1")
	if len(inv.Probes) != 0 {
		t.Fatalf("orphan update fabricated a probe: %+v", inv.Probes)
	}
}
