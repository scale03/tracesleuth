package event

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// VerifyResult summarizes a chain verification pass.
type VerifyResult struct {
	Lines int  // number of JSONL lines checked
	OK    bool // true iff no gap/tamper was found
}

// VerifyReader walks a JSONL stream and confirms the audit chain is intact:
//   - seq numbers start at 0 and increase by exactly 1 (no gaps, no reordering),
//   - each line's prev_hash equals the previous line's hash,
//   - each line's stored hash equals sha256(prev_hash + canonical content).
//
// The first problem found is returned as an error naming the offending line, so
// a tampered or missing line is pinpointed rather than reported vaguely. This is
// the Phase 0 "cheapest possible proof" that the audit design holds.
func VerifyReader(r io.Reader) (VerifyResult, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)

	var (
		count    int
		expSeq   int
		prevHash string
	)
	for sc.Scan() {
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(raw, &e); err != nil {
			return VerifyResult{Lines: count}, fmt.Errorf("line %d: not valid JSON: %w", count, err)
		}

		if e.Seq != expSeq {
			return VerifyResult{Lines: count}, fmt.Errorf(
				"line %d: seq gap/reorder: expected seq=%d, got seq=%d (a line was inserted, removed, or reordered)",
				count, expSeq, e.Seq)
		}
		// prev_hash null on the wire unmarshals to "" — same as genesis.
		if e.PrevHash != prevHash {
			return VerifyResult{Lines: count}, fmt.Errorf(
				"line %d (seq=%d): prev_hash %q does not chain to previous line's hash %q",
				count, e.Seq, short(e.PrevHash), short(prevHash))
		}
		if err := verifyHash(e); err != nil {
			return VerifyResult{Lines: count}, fmt.Errorf(
				"line %d (seq=%d, event=%s): %w — this line's content was altered after signing",
				count, e.Seq, e.Event, err)
		}

		prevHash = e.Hash
		expSeq++
		count++
	}
	if err := sc.Err(); err != nil {
		return VerifyResult{Lines: count}, err
	}
	return VerifyResult{Lines: count, OK: true}, nil
}

// VerifyFile is VerifyReader over a file path.
func VerifyFile(path string) (VerifyResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return VerifyResult{}, err
	}
	defer f.Close()
	return VerifyReader(f)
}
