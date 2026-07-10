# Architecture

## The one invariant

Every meaningful step of an investigation is written to an **append-only,
hash-chained JSONL log before or as it happens**. That log is the source of
truth. Everything else — the SQLite index, the CLI output, any future UI — is a
projection that can be thrown away and rebuilt from it. Design decisions are
judged by one question: *does this make the hypothesis → probe → result chain
easier or harder to reconstruct?*

## Data flow

```
                       ┌──────────────────────────────────────────────┐
  tracectl / (later)   │                  service                      │
  Teleport transport ─▶│  Open ─ Hypothesis ─ RunProbe ─ Close         │
                       │                     │                         │
                       │   ┌── dry-run ──────┤ (exec.DryRun)           │
                       │   ├── policy ───────┤ (internal/policy)       │
                       │   └── execute ──────┤ (exec.Executor)         │
                       └───────────┬─────────┴────────────┬────────────┘
                                   │ append (hash-chained)  │ project
                                   ▼                        ▼
                       logs/<inv>.jsonl  ──reindex──▶  index.db (SQLite)
                        (source of truth)              (query layer)
                                   │
                                   └── outputs/<inv>/<probe>.log  (raw, referenced by hash+path)
```

## Why append-log + SQLite, not one or the other

The JSONL log is simple, human-readable, tail-able, and hash-chainable for
tamper evidence — it survives even if the database is corrupted. SQLite is what
the query layer reads for "every investigation on host X in the last 24h that
used a kprobe." If the DB is lost or its schema changes, `tracectl reindex`
replays the logs and rebuilds it. This mirrors journald / Kafka+materialized
views: append log = truth, database = queryable projection.

## The hash chain

`hash = sha256(prev_hash || canonical_json)` where `canonical_json` is the event
serialized with its own `hash` field blanked (struct field order makes this
deterministic — no separate canonicalization pass). `prev_hash` is part of the
hashed content, so altering any earlier line changes every later hash. The
verifier checks three things per line: seq is contiguous from 0, `prev_hash`
matches the previous line's `hash`, and the stored `hash` recomputes. See
`internal/event`.

`script_text` is stored **inline** in the log, not just its hash — you should
never have to hunt down a script elsewhere to know what ran. Raw probe output is
the exception: it goes to a separate file referenced by path + sha256, to keep
the event log small and greppable.

## Seams built for later phases

- **`exec.Executor`** — the daemon depends only on this interface. Real bpftrace
  (Linux, sudo-scoped) and the deterministic mock are interchangeable; the audit
  log records which backend ran (`Result.Backend`) so a mock is never mistaken
  for a real capture. Real bpftrace enforces `Spec.Duration` itself (SIGINT at
  the deadline so maps flush, SIGKILL only if it overstays) rather than trusting
  the script.
- **`service.Identity`** — populated from a CLI flag today; in Phase 2 the same
  struct is filled from a Teleport certificate by an `IdentityResolver`, and
  nothing downstream (policy input, JSONL schema) changes. This is what keeps
  "SSH now, mTLS later" cheap instead of a rewrite.
- **`internal/catalog`** — the catalog source that `list_probe_catalog` advertises
  *and* that feeds policy as the `data.catalog` document (caps, high-frequency set,
  deny-lists). Loadable from JSON (`TRACESLEUTH_CATALOG`) so it can change without
  a rebuild; falls back to the compiled `Default()`.
- **Policy — OPA at runtime, default-allow + deny-list** (bundle 2026.07.02). The
  daemon evaluates `policy.rego` in-process via the embedded OPA SDK
  (`internal/policy/engine.go`); the Rego, loadable from disk (`TRACESLEUTH_POLICY`,
  else an embedded byte-identical copy), is the single source of truth — no more Go
  rule mirror. Posture is **default-allow**: the host has full bpftrace capability,
  and policy only carves out what is forbidden (explicit deny-lists) and constrains
  *modality* (duration caps, high-frequency-must-aggregate, first-probe scoping,
  concurrency). `internal/policy/policy.rego` is kept byte-identical to
  `policy/policy.rego` by a guard test; `opa test ./policy/...` runs in CI. Both the
  MCP server and `tracectl` load policy through one shared `service.PolicyFromEnv`,
  so every entry point enforces identically. See `deploy/policy/README.md`.
  *Trust note:* the boundary is now the on-disk `policy.rego`/`catalog.json` (gated
  by the launching Teleport identity), not the signed binary.

## Keeping the agent from drowning in output

Three independent layers, by design:

1. **Policy as a shape linter** — high-frequency attach points must use an
   aggregation (`count/sum/hist/@map`), not raw per-event output. Denials are
   actionable ("add an aggregation"), so an agent retries correctly instead of
   guessing.
2. **Coarse-then-narrow** — the first probe of an investigation may not be a
   long, unscoped, unaggregated capture; go wide-and-cheap first, then narrow.
3. **Output shaping** (`internal/output`, separate from policy) — inline results
   are summarized (head+tail / top-N) and hard-capped at 50KB; the full capture
   always lands on disk, retrievable with a cheap follow-up read.

## Deferred (designed, not built)

- **Phase 2 — Teleport transport** (SSH via `tsh` and mTLS via `tbot`, both
  behind `IdentityResolver`). Needs a Teleport cluster; not stood up here.
- **Phase 4 — cgroup resource guards** around real bpftrace execution.
- **Phase 7 — Baselines** as a second first-class resource (continuous,
  async, TTL enforced twice), with `baselines` / `investigation_baseline_refs`
  tables and `baseline_*` events.

See [`status.md`](status.md) for the exact per-phase state.
