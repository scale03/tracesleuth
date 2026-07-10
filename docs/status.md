# Phase status

Honest state of each phase from the development plan. "Done when" criteria are
quoted from the plan.

| Phase | State | Notes |
|---|---|---|
| **0 — Schema & event contract** | ✅ Done | JSONL contract (`internal/event`), hash chain, and `verify-chain` tool. *Done when:* a tampered line is flagged — verified (`scripts/tamper_test.sh`). |
| **1 — Single-host core** | ✅ Done | `tracectl` drives open→hypothesis→probe→close locally, writes JSONL, shells to bpftrace (or mock), updates SQLite. *Done when:* full chain reconstructable from the index alone — verified (`TestEndToEndChainReconstructable`, `tracectl show`). |
| **2 — Mac↔Linux Teleport transport** | ⛔ Not built | No Teleport cluster available. `service.Identity` + a future `IdentityResolver` are the designed seam; identity is currently a CLI flag and **unverified** (see SECURITY.md). |
| **3 — OPA policy check** | ◐ Core done, embedded | Policy runs before `probe_started`; every decision incl. denials logged with an actionable reason. Implemented in Go (`internal/policy`) for on-host decisions **and** as reviewable Rego (`policy/*.rego`, `opa test` green). Not yet run as a standalone OPA server (deferred by design). |
| **4 — Probe safety / validation** | ◐ Partial | `--dry-run` parse check before policy ✅ (real bpftrace backend). Attach-point allow-list ✅ (`internal/catalog`). cgroup CPU/memory guards ⛔ not implemented. |
| **5 — Second host / team rollout** | ⛔ Not built | `host` field exists everywhere already; needs Teleport roles + a `policy/` CI job (workflow added) + join-token onboarding. |
| **6 — Query / inspection** | ✅ Done | `tracectl show <id>`, `tracectl list --filter-host=…`, `reindex`, `verify` read the SQLite index. |
| **7 — Baselines (sync/async)** | ⛔ Not built | Designed: distinct resource type, TTL enforced twice, `baseline_*` events, `baselines` table. No code yet. |
| **8 — Harness visibility & discovery** | ✅ Core done | Response shape (status → script → decision) via `ProbeReport.Render`; `list_probe_catalog` = `tracectl catalog`, reading the same allow-list policy enforces. |
| **Output shaping** ("drowning") | ✅ Done | Aggregation-required policy rule + coarse-then-narrow rule + `internal/output` summary/50KB cap. |

## Verified on real hardware

Built and tested on Fedora 43 (kernel 6.18), Go 1.25, bpftrace v0.24.2:
`go test ./...` and `opa test ./policy/...` both green. The mock backend proves
the full chain without root; the real bpftrace backend runs once a sudoers rule
scoped to `/usr/bin/bpftrace` is in place (see README).
