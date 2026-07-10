package event

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// Log is an append-only writer for one investigation's JSONL file. It is the
// only thing that assigns seq numbers and chains hashes, so all writes for an
// investigation must go through a single Log instance.
type Log struct {
	mu       sync.Mutex
	path     string
	f        *os.File
	w        *bufio.Writer
	nextSeq  int
	prevHash string
}

// OpenLog opens (creating if needed) the JSONL file for an investigation and
// recovers the current seq/prev_hash by scanning any existing content, so a
// restarted daemon continues the chain instead of forking it.
func OpenLog(dir, investigationID string) (*Log, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, investigationID+".jsonl")

	// Recover tail state from whatever is already on disk.
	nextSeq, prevHash, err := tailState(path)
	if err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return nil, err
	}
	return &Log{
		path:     path,
		f:        f,
		w:        bufio.NewWriter(f),
		nextSeq:  nextSeq,
		prevHash: prevHash,
	}, nil
}

// Path returns the on-disk path of the JSONL file.
func (l *Log) Path() string { return l.path }

// Append fills in the envelope fields (seq, ts, prev_hash, hash), writes the
// line, and flushes+fsyncs so the audit record survives a crash. It returns the
// completed event so callers can feed the same values into the SQLite index.
func (l *Log) Append(e Event) (Event, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	e.Seq = l.nextSeq
	if e.TS == "" {
		e.TS = Now()
	}
	e.PrevHash = l.prevHash

	h, err := ComputeHash(e)
	if err != nil {
		return Event{}, err
	}
	e.Hash = h

	line, err := json.Marshal(e)
	if err != nil {
		return Event{}, err
	}
	if _, err := l.w.Write(append(line, '\n')); err != nil {
		return Event{}, err
	}
	if err := l.w.Flush(); err != nil {
		return Event{}, err
	}
	// Durability: an audit log that can lose its last line on power failure is
	// not an audit log. fsync every append — probe rates are human-scale here.
	if err := l.f.Sync(); err != nil {
		return Event{}, err
	}

	l.nextSeq++
	l.prevHash = h
	return e, nil
}

// Close flushes and closes the underlying file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.w.Flush(); err != nil {
		l.f.Close()
		return err
	}
	return l.f.Close()
}

// tailState scans an existing JSONL file and returns the next seq number and
// the last line's hash, so appends continue the chain. A missing file starts a
// fresh chain (seq 0, prev_hash "").
func tailState(path string) (nextSeq int, prevHash string, err error) {
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		return 0, "", nil
	}
	if err != nil {
		return 0, "", err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024) // scripts can be large
	var last *Event
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return 0, "", fmt.Errorf("corrupt tail in %s: %w", path, err)
		}
		ev := e
		last = &ev
	}
	if err := sc.Err(); err != nil {
		return 0, "", err
	}
	if last == nil {
		return 0, "", nil
	}
	return last.Seq + 1, last.Hash, nil
}
