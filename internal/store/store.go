// Package store is the SQLite index: a disposable, queryable projection of the
// append-only JSONL logs. It is never the source of truth — if it is deleted or
// its schema changes, Rebuild replays the JSONL files and reconstructs it. The
// query layer (tracectl show/list) reads only from here.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"

	_ "modernc.org/sqlite" // pure-Go driver, no cgo

	"tracesleuth/internal/event"
)

// Store wraps the SQLite index database.
type Store struct {
	db *sql.DB
}

// Open opens (and migrates) the index at path. Use ":memory:" in tests.
func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	if _, err := db.Exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;`); err != nil {
		db.Close()
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(schema)
	return err
}

const schema = `
CREATE TABLE IF NOT EXISTS investigations (
  id TEXT PRIMARY KEY,
  agent_identity TEXT NOT NULL,
  host TEXT NOT NULL,
  opened_at TEXT NOT NULL,
  closed_at TEXT,
  hypothesis TEXT NOT NULL DEFAULT '',
  conclusion TEXT,
  status TEXT NOT NULL          -- open | closed | aborted
);

CREATE TABLE IF NOT EXISTS probes (
  id TEXT PRIMARY KEY,
  investigation_id TEXT NOT NULL REFERENCES investigations(id),
  script_sha256 TEXT NOT NULL,
  script_text TEXT NOT NULL,
  probe_types TEXT NOT NULL,      -- JSON array
  attach_points TEXT NOT NULL,    -- JSON array
  duration_s INTEGER,
  policy_decision TEXT NOT NULL DEFAULT '',  -- allow | deny | needs_approval
  policy_bundle_version TEXT,
  started_at TEXT,
  ended_at TEXT,
  exit_code INTEGER,
  output_path TEXT,
  output_sha256 TEXT
);

CREATE INDEX IF NOT EXISTS idx_probes_investigation ON probes(investigation_id);
CREATE INDEX IF NOT EXISTS idx_probes_script_hash ON probes(script_sha256);
`

// Apply folds a single audit event into the index. It is idempotent per event
// (INSERT OR IGNORE + targeted UPDATEs), so replaying a whole JSONL file or
// applying events live both converge to the same state.
func (s *Store) Apply(e event.Event) error {
	switch e.Event {
	case event.InvestigationOpened:
		_, err := s.db.Exec(`
			INSERT INTO investigations (id, agent_identity, host, opened_at, status, hypothesis)
			VALUES (?, ?, ?, ?, 'open', '')
			ON CONFLICT(id) DO UPDATE SET
			  agent_identity=excluded.agent_identity, host=excluded.host, opened_at=excluded.opened_at`,
			e.InvestigationID, e.AgentIdentity, e.Host, e.TS)
		return err

	case event.HypothesisDeclared:
		_, err := s.db.Exec(`UPDATE investigations SET hypothesis=? WHERE id=?`, e.Text, e.InvestigationID)
		return err

	case event.ProbeProposed:
		pt, _ := json.Marshal(e.ProbeTypes)
		ap, _ := json.Marshal(e.AttachPoints)
		var dur any
		if e.DurationS != nil {
			dur = *e.DurationS
		}
		_, err := s.db.Exec(`
			INSERT INTO probes (id, investigation_id, script_sha256, script_text, probe_types, attach_points, duration_s)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
			  script_sha256=excluded.script_sha256, script_text=excluded.script_text,
			  probe_types=excluded.probe_types, attach_points=excluded.attach_points,
			  duration_s=excluded.duration_s`,
			e.ProbeID, e.InvestigationID, e.ScriptSHA256, e.ScriptText, string(pt), string(ap), dur)
		return err

	case event.PolicyDecision:
		_, err := s.db.Exec(`UPDATE probes SET policy_decision=?, policy_bundle_version=? WHERE id=?`,
			e.Decision, e.PolicyBundleVersion, e.ProbeID)
		return err

	case event.ProbeStarted:
		_, err := s.db.Exec(`UPDATE probes SET started_at=? WHERE id=?`, e.TS, e.ProbeID)
		return err

	case event.ProbeEnded:
		var ec any
		if e.ExitCode != nil {
			ec = *e.ExitCode
		}
		_, err := s.db.Exec(`UPDATE probes SET ended_at=?, exit_code=?, output_path=?, output_sha256=? WHERE id=?`,
			e.TS, ec, e.OutputPath, e.OutputSHA256, e.ProbeID)
		return err

	case event.InvestigationClosed:
		_, err := s.db.Exec(`UPDATE investigations SET status='closed', closed_at=?, conclusion=? WHERE id=?`,
			e.TS, e.Conclusion, e.InvestigationID)
		return err
	}
	return nil
}

// Reset drops all projected rows (not the schema) so Rebuild can repopulate from
// scratch without stale entries.
func (s *Store) Reset() error {
	_, err := s.db.Exec(`DELETE FROM probes; DELETE FROM investigations;`)
	return err
}

// Investigation is a row of the investigations table plus its probes.
type Investigation struct {
	ID            string
	AgentIdentity string
	Host          string
	OpenedAt      string
	ClosedAt      string
	Hypothesis    string
	Conclusion    string
	Status        string
	Probes        []Probe
}

// Probe is a row of the probes table.
type Probe struct {
	ID             string
	ScriptSHA256   string
	ScriptText     string
	ProbeTypes     string
	AttachPoints   string
	DurationS      sql.NullInt64
	PolicyDecision string
	PolicyBundle   string
	StartedAt      string
	EndedAt        string
	ExitCode       sql.NullInt64
	OutputPath     string
	OutputSHA256   string
}

// Get returns one investigation with its probes, or ok=false if not found.
func (s *Store) Get(id string) (Investigation, bool, error) {
	var inv Investigation
	var closedAt, conclusion sql.NullString
	err := s.db.QueryRow(`
		SELECT id, agent_identity, host, opened_at, closed_at, hypothesis, conclusion, status
		FROM investigations WHERE id=?`, id).
		Scan(&inv.ID, &inv.AgentIdentity, &inv.Host, &inv.OpenedAt, &closedAt, &inv.Hypothesis, &conclusion, &inv.Status)
	if err == sql.ErrNoRows {
		return Investigation{}, false, nil
	}
	if err != nil {
		return Investigation{}, false, err
	}
	inv.ClosedAt, inv.Conclusion = closedAt.String, conclusion.String

	probes, err := s.probesFor(id)
	if err != nil {
		return Investigation{}, false, err
	}
	inv.Probes = probes
	return inv, true, nil
}

func (s *Store) probesFor(invID string) ([]Probe, error) {
	rows, err := s.db.Query(`
		SELECT id, script_sha256, script_text, probe_types, attach_points, duration_s,
		       policy_decision, policy_bundle_version, started_at, ended_at, exit_code, output_path, output_sha256
		FROM probes WHERE investigation_id=? ORDER BY started_at, id`, invID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Probe
	for rows.Next() {
		var p Probe
		var bundle, started, ended, opath, osha sql.NullString
		if err := rows.Scan(&p.ID, &p.ScriptSHA256, &p.ScriptText, &p.ProbeTypes, &p.AttachPoints, &p.DurationS,
			&p.PolicyDecision, &bundle, &started, &ended, &p.ExitCode, &opath, &osha); err != nil {
			return nil, err
		}
		p.PolicyBundle, p.StartedAt, p.EndedAt, p.OutputPath, p.OutputSHA256 = bundle.String, started.String, ended.String, opath.String, osha.String
		out = append(out, p)
	}
	return out, rows.Err()
}

// ListFilter narrows a List query. Zero values mean "no constraint".
type ListFilter struct {
	Host   string
	Status string
	Since  string // opened_at >= this (RFC3339); empty = no bound
	Limit  int
}

// List returns investigation summaries (without probes) matching the filter.
func (s *Store) List(f ListFilter) ([]Investigation, error) {
	q := `SELECT id, agent_identity, host, opened_at, closed_at, hypothesis, conclusion, status
	      FROM investigations WHERE 1=1`
	var args []any
	if f.Host != "" {
		q += ` AND host=?`
		args = append(args, f.Host)
	}
	if f.Status != "" {
		q += ` AND status=?`
		args = append(args, f.Status)
	}
	if f.Since != "" {
		q += ` AND opened_at >= ?`
		args = append(args, f.Since)
	}
	q += ` ORDER BY opened_at DESC`
	if f.Limit > 0 {
		q += fmt.Sprintf(` LIMIT %d`, f.Limit)
	}

	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Investigation
	for rows.Next() {
		var inv Investigation
		var closedAt, conclusion sql.NullString
		if err := rows.Scan(&inv.ID, &inv.AgentIdentity, &inv.Host, &inv.OpenedAt, &closedAt,
			&inv.Hypothesis, &conclusion, &inv.Status); err != nil {
			return nil, err
		}
		inv.ClosedAt, inv.Conclusion = closedAt.String, conclusion.String
		out = append(out, inv)
	}
	return out, rows.Err()
}
