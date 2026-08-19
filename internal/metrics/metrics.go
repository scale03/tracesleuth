// Package metrics is the Prometheus backing for the service's Metrics interface.
// It lives apart from the service so that layer stays dependency-free and the
// daemon is the only thing that pulls in the Prometheus client.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Prometheus implements service.Metrics against a private registry.
type Prometheus struct {
	reg       *prometheus.Registry
	opened    prometheus.Counter
	decisions *prometheus.CounterVec
	duration  prometheus.Histogram
	running   prometheus.Gauge
}

// New builds the collectors and registers them. Each metric is namespaced
// tracesleuth_ so it reads clearly in a shared Prometheus.
func New() *Prometheus {
	p := &Prometheus{
		reg: prometheus.NewRegistry(),
		opened: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "tracesleuth_investigations_opened_total",
			Help: "Investigations opened.",
		}),
		decisions: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "tracesleuth_probe_decisions_total",
			Help: "Probe policy decisions, by outcome.",
		}, []string{"decision"}),
		duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "tracesleuth_probe_duration_seconds",
			Help:    "Wall-clock duration of probes that ran.",
			Buckets: []float64{0.1, 0.5, 1, 2, 5, 10, 30, 60, 120, 300},
		}),
		running: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "tracesleuth_probes_running",
			Help: "Probes currently attached to the kernel.",
		}),
	}
	p.reg.MustRegister(p.opened, p.decisions, p.duration, p.running)
	// Pre-create the label series so a scrape shows 0 before the first decision.
	p.decisions.WithLabelValues("allow")
	p.decisions.WithLabelValues("deny")
	return p
}

// Handler serves the exposition format for this registry.
func (p *Prometheus) Handler() http.Handler {
	return promhttp.HandlerFor(p.reg, promhttp.HandlerOpts{})
}

func (p *Prometheus) InvestigationOpened()          { p.opened.Inc() }
func (p *Prometheus) ProbeDecided(decision string)  { p.decisions.WithLabelValues(decision).Inc() }
func (p *Prometheus) ProbeObserved(d time.Duration) { p.duration.Observe(d.Seconds()) }

func (p *Prometheus) ProbeRunning(delta int) {
	if delta >= 0 {
		p.running.Add(float64(delta))
	} else {
		p.running.Sub(float64(-delta))
	}
}
