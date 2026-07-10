// Command verify-chain is the Phase 0 audit verifier: given one or more JSONL
// investigation logs, it walks each file and confirms there are no gaps and no
// tampering (seq contiguity + prev_hash chaining + per-line hash recompute). It
// exits non-zero if any file fails, so it drops straight into CI or a pre-commit
// check. This is the cheapest possible proof that the audit design holds before
// anything else is built on it.
package main

import (
	"fmt"
	"os"

	"tracesleuth/internal/event"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: verify-chain <file.jsonl> [more.jsonl ...]")
		os.Exit(2)
	}
	failed := false
	for _, path := range os.Args[1:] {
		res, err := event.VerifyFile(path)
		if err != nil {
			failed = true
			fmt.Printf("✗ %s\n    TAMPERED: %v\n", path, err)
			continue
		}
		fmt.Printf("✓ %s — intact (%d lines)\n", path, res.Lines)
	}
	if failed {
		os.Exit(1)
	}
}
