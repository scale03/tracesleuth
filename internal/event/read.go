package event

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
)

// ReadFile parses every line of one investigation's JSONL file into events, in
// file order. It does not verify the chain — use VerifyFile for that.
func ReadFile(path string) ([]Event, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	var out []Event
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// ReadDir reads every *.jsonl file in dir and returns their events. Files are
// processed in sorted filename order; within a file, line order is preserved.
// This is what a Rebuild replays.
func ReadDir(dir string) ([]Event, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.jsonl"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	var out []Event
	for _, m := range matches {
		evs, err := ReadFile(m)
		if err != nil {
			return nil, err
		}
		out = append(out, evs...)
	}
	return out, nil
}
