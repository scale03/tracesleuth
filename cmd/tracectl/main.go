// Command tracectl is the single-host CLI for TraceSleuth (Phase 1 + Phase 6).
// It drives investigations locally (no network yet) and reads the SQLite index
// to reconstruct exactly what happened. Subcommands:
//
//	catalog     list allowed probe types / attach points (list_probe_catalog)
//	open        open an investigation, print its id
//	hypothesis  record the hypothesis under test
//	probe       propose+validate+policy-check+run one probe
//	close       record the conclusion and close
//	show        print an investigation's full chain from the index
//	list        list investigations, optionally filtered by host/status
//	reindex     rebuild the SQLite index from the JSONL source of truth
//	verify      verify the hash chain of one or all investigations
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"tracesleuth/internal/catalog"
	"tracesleuth/internal/service"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "catalog":
		err = cmdCatalog(args)
	case "open":
		err = cmdOpen(args)
	case "hypothesis":
		err = cmdHypothesis(args)
	case "probe":
		err = cmdProbe(args)
	case "close":
		err = cmdClose(args)
	case "show":
		err = cmdShow(args)
	case "list":
		err = cmdList(args)
	case "reindex":
		err = cmdReindex(args)
	case "verify":
		err = cmdVerify(args)
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", cmd)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `tracectl — TraceSleuth single-host CLI

usage: tracectl <command> [flags]

commands:
  catalog                          show allowed probes/attach points
  open        --identity N --host H [--roles a,b]
  hypothesis  --inv ID --text "..."
  probe       --inv ID --script S|--script-file F --type T --attach A [--duration N] [--filter-pid] [--filter-comm]
  close       --inv ID --conclusion "..."
  show        --inv ID
  list        [--host H] [--status S] [--limit N]
  reindex
  verify      [--inv ID | --all]

global: --data DIR (default ./data), --host NAME (default hostname)
`)
}

// svc constructs a Service from the shared --data/--host flags. Catalog and
// policy come from the same TRACESLEUTH_CATALOG/TRACESLEUTH_POLICY loader the MCP
// server uses, so the CLI enforces identical policy.
func svc(fs *flag.FlagSet, data, host *string) (*service.Service, error) {
	if *host == "" {
		h, _ := os.Hostname()
		*host = h
	}
	cat, engine, err := service.PolicyFromEnv()
	if err != nil {
		return nil, err
	}
	return service.New(service.Config{DataDir: *data, Host: *host, Catalog: cat, Policy: engine})
}

func stdFlags(fs *flag.FlagSet) (data, host *string) {
	data = fs.String("data", "./data", "data directory")
	host = fs.String("host", "", "host name (default: OS hostname)")
	return
}

func cmdCatalog(args []string) error {
	fs := flag.NewFlagSet("catalog", flag.ExitOnError)
	data, host := stdFlags(fs)
	fs.Parse(args)
	s, err := svc(fs, data, host)
	if err != nil {
		return err
	}
	defer s.Close()
	printCatalog(s.Catalog())
	return nil
}

func cmdOpen(args []string) error {
	fs := flag.NewFlagSet("open", flag.ExitOnError)
	data, host := stdFlags(fs)
	identity := fs.String("identity", "", "agent/user identity (required)")
	roles := fs.String("roles", "", "comma-separated roles")
	fs.Parse(args)
	if *identity == "" {
		return fmt.Errorf("--identity is required")
	}
	s, err := svc(fs, data, host)
	if err != nil {
		return err
	}
	defer s.Close()
	id, err := s.Open(service.Identity{Name: *identity, Roles: splitCSV(*roles)})
	if err != nil {
		return err
	}
	fmt.Println(id)
	return nil
}

func cmdHypothesis(args []string) error {
	fs := flag.NewFlagSet("hypothesis", flag.ExitOnError)
	data, host := stdFlags(fs)
	inv := fs.String("inv", "", "investigation id (required)")
	text := fs.String("text", "", "hypothesis text (required)")
	fs.Parse(args)
	if *inv == "" || *text == "" {
		return fmt.Errorf("--inv and --text are required")
	}
	s, err := svc(fs, data, host)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Hypothesis(*inv, *text)
}

func cmdProbe(args []string) error {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	data, host := stdFlags(fs)
	inv := fs.String("inv", "", "investigation id (required)")
	script := fs.String("script", "", "bpftrace script text")
	scriptFile := fs.String("script-file", "", "path to a bpftrace script file")
	types := fs.String("type", "", "comma-separated probe types, e.g. kprobe")
	attach := fs.String("attach", "", "comma-separated attach points")
	duration := fs.Int("duration", 0, "duration seconds (0 = catalog default)")
	filterPID := fs.Bool("filter-pid", false, "script is scoped by pid")
	filterComm := fs.Bool("filter-comm", false, "script is scoped by comm")
	fs.Parse(args)
	if *inv == "" {
		return fmt.Errorf("--inv is required")
	}
	scriptText := *script
	if *scriptFile != "" {
		b, err := os.ReadFile(*scriptFile)
		if err != nil {
			return err
		}
		scriptText = string(b)
	}
	if strings.TrimSpace(scriptText) == "" {
		return fmt.Errorf("provide --script or --script-file")
	}
	s, err := svc(fs, data, host)
	if err != nil {
		return err
	}
	defer s.Close()
	rep, err := s.RunProbe(context.Background(), *inv, service.ProbeRequest{
		ProbeTypes:   splitCSV(*types),
		AttachPoints: splitCSV(*attach),
		ScriptText:   scriptText,
		DurationS:    *duration,
		FilterPID:    *filterPID,
		FilterComm:   *filterComm,
	}, nil)
	if err != nil {
		return err
	}
	fmt.Print(rep.Render())
	if rep.Decision == "deny" {
		os.Exit(3) // distinct exit code so scripts can detect a policy denial
	}
	return nil
}

func cmdClose(args []string) error {
	fs := flag.NewFlagSet("close", flag.ExitOnError)
	data, host := stdFlags(fs)
	inv := fs.String("inv", "", "investigation id (required)")
	conclusion := fs.String("conclusion", "", "conclusion text (required)")
	fs.Parse(args)
	if *inv == "" || *conclusion == "" {
		return fmt.Errorf("--inv and --conclusion are required")
	}
	s, err := svc(fs, data, host)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Close_(*inv, *conclusion)
}

func cmdReindex(args []string) error {
	fs := flag.NewFlagSet("reindex", flag.ExitOnError)
	data, host := stdFlags(fs)
	fs.Parse(args)
	s, err := svc(fs, data, host)
	if err != nil {
		return err
	}
	defer s.Close()
	n, err := s.Reindex()
	if err != nil {
		return err
	}
	fmt.Printf("reindexed %d events from %s\n", n, s.LogsDir())
	return nil
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func printCatalog(c catalog.Catalog) {
	fmt.Printf("catalog bundle %s — default duration %ds, max %ds, max concurrent %d\n",
		c.BundleVersion, c.DefaultDuration, c.MaxDuration, c.MaxConcurrent)
	fmt.Printf("probe types: %s\n\n", strings.Join(c.ProbeTypes, ", "))
	for _, cat := range []catalog.Category{catalog.Network, catalog.Process, catalog.DiskIO, catalog.Scheduler} {
		aps := c.GroupByCategory()[cat]
		if len(aps) == 0 {
			continue
		}
		fmt.Printf("[%s]\n", cat)
		for _, ap := range aps {
			flag := ""
			if ap.HighFrequency {
				flag = "  ⚠ high-frequency: requires aggregation (count/sum/hist/map)"
			}
			fmt.Printf("  %-22s %s%s\n", ap.Name, ap.Description, flag)
		}
		fmt.Println()
	}
}

// dataPath resolves a path inside the data dir (used by show for output files).
func dataPath(data, rel string) string { return filepath.Join(data, rel) }
