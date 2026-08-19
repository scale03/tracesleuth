package metrics

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"tracesleuth/internal/service"
)

// Prometheus must satisfy the interface the service records against.
var _ service.Metrics = (*Prometheus)(nil)

func TestExpositionReflectsSignals(t *testing.T) {
	p := New()
	p.InvestigationOpened()
	p.ProbeDecided("allow")
	p.ProbeDecided("deny")
	p.ProbeDecided("deny")
	p.ProbeObserved(2 * time.Second)
	p.ProbeRunning(1)

	body := scrape(t, p)
	for _, want := range []string{
		`tracesleuth_investigations_opened_total 1`,
		`tracesleuth_probe_decisions_total{decision="allow"} 1`,
		`tracesleuth_probe_decisions_total{decision="deny"} 2`,
		`tracesleuth_probes_running 1`,
		`tracesleuth_probe_duration_seconds_count 1`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("exposition missing %q\n---\n%s", want, body)
		}
	}
}

// The running gauge goes back down when a probe ends.
func TestRunningGaugeBalances(t *testing.T) {
	p := New()
	p.ProbeRunning(1)
	p.ProbeRunning(1)
	p.ProbeRunning(-1)
	if !strings.Contains(scrape(t, p), "tracesleuth_probes_running 1") {
		t.Fatal("gauge did not net to 1")
	}
}

func scrape(t *testing.T, p *Prometheus) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	w := httptest.NewRecorder()
	p.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("scrape status %d", w.Code)
	}
	return w.Body.String()
}
