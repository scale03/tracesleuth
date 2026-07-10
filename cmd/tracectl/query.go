package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"tracesleuth/internal/event"
	"tracesleuth/internal/store"
)

func cmdShow(args []string) error {
	fs := flag.NewFlagSet("show", flag.ExitOnError)
	data, host := stdFlags(fs)
	inv := fs.String("inv", "", "investigation id (required)")
	fs.Parse(args)
	if *inv == "" {
		return fmt.Errorf("--inv is required")
	}
	s, err := svc(fs, data, host)
	if err != nil {
		return err
	}
	defer s.Close()

	iv, ok, err := s.Store().Get(*inv)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("investigation %s not found (try: tracectl reindex)", *inv)
	}

	fmt.Printf("Investigation %s  [%s]\n", iv.ID, iv.Status)
	fmt.Printf("  host:       %s\n", iv.Host)
	fmt.Printf("  identity:   %s\n", iv.AgentIdentity)
	fmt.Printf("  opened:     %s\n", iv.OpenedAt)
	if iv.ClosedAt != "" {
		fmt.Printf("  closed:     %s\n", iv.ClosedAt)
	}
	fmt.Printf("  hypothesis: %s\n", iv.Hypothesis)
	if iv.Conclusion != "" {
		fmt.Printf("  conclusion: %s\n", iv.Conclusion)
	}
	fmt.Printf("\n  probes (%d):\n", len(iv.Probes))
	for _, p := range iv.Probes {
		fmt.Printf("  ─ %s  decision=%s", p.ID, p.PolicyDecision)
		if p.DurationS.Valid {
			fmt.Printf(" duration=%ds", p.DurationS.Int64)
		}
		if p.ExitCode.Valid {
			fmt.Printf(" exit=%d", p.ExitCode.Int64)
		}
		fmt.Println()
		fmt.Printf("      attach=%s types=%s\n", trimJSON(p.AttachPoints), trimJSON(p.ProbeTypes))
		fmt.Printf("      script: %s\n", oneLine(p.ScriptText))
		if p.OutputPath != "" {
			fmt.Printf("      output: %s  sha256=%s\n", p.OutputPath, short12(p.OutputSHA256))
			// Show that "understand exactly what happened" is one hop away.
			if b, err := os.ReadFile(dataPath(*data, p.OutputPath)); err == nil {
				fmt.Printf("      (%d bytes captured; head: %s)\n", len(b), oneLine(string(b)))
			}
		}
	}
	return nil
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	data, host := stdFlags(fs)
	fHost := fs.String("filter-host", "", "filter by host")
	status := fs.String("status", "", "filter by status (open|closed)")
	limit := fs.Int("limit", 50, "max rows")
	fs.Parse(args)
	s, err := svc(fs, data, host)
	if err != nil {
		return err
	}
	defer s.Close()

	invs, err := s.Store().List(store.ListFilter{Host: *fHost, Status: *status, Limit: *limit})
	if err != nil {
		return err
	}
	if len(invs) == 0 {
		fmt.Println("no investigations (try: tracectl reindex)")
		return nil
	}
	for _, iv := range invs {
		fmt.Printf("%-12s %-10s %-16s %-8s %s\n", iv.ID, iv.Status, iv.Host, iv.OpenedAt[11:min(19, len(iv.OpenedAt))], oneLine(iv.Hypothesis))
	}
	return nil
}

func cmdVerify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	data, host := stdFlags(fs)
	inv := fs.String("inv", "", "investigation id")
	all := fs.Bool("all", false, "verify every investigation")
	fs.Parse(args)
	s, err := svc(fs, data, host)
	if err != nil {
		return err
	}
	defer s.Close()

	var files []string
	if *all || *inv == "" {
		matches, _ := filepath.Glob(filepath.Join(s.LogsDir(), "*.jsonl"))
		files = matches
	} else {
		files = []string{filepath.Join(s.LogsDir(), *inv+".jsonl")}
	}
	if len(files) == 0 {
		return fmt.Errorf("no JSONL logs found in %s", s.LogsDir())
	}

	failed := false
	for _, f := range files {
		res, err := event.VerifyFile(f)
		name := strings.TrimSuffix(filepath.Base(f), ".jsonl")
		if err != nil {
			failed = true
			fmt.Printf("✗ %-12s TAMPERED: %v\n", name, err)
			continue
		}
		fmt.Printf("✓ %-12s intact (%d lines)\n", name, res.Lines)
	}
	if failed {
		os.Exit(4)
	}
	return nil
}

func trimJSON(s string) string {
	s = strings.TrimPrefix(s, "[")
	s = strings.TrimSuffix(s, "]")
	return strings.ReplaceAll(s, "\"", "")
}

func oneLine(s string) string {
	s = strings.ReplaceAll(strings.ReplaceAll(s, "\n", " "), "\t", " ")
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > 90 {
		return s[:90] + "…"
	}
	return s
}

func short12(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12] + "…"
}
