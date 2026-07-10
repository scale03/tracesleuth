# Editable policy & catalog

TraceSleuth evaluates its policy at **runtime** with OPA, and reads its catalog
data from disk. That means you can change what probes are allowed — and under
what modality — **without recompiling or redeploying the binary**. Edit a file,
reconnect the MCP session (or re-run `tracectl`), done.

## Posture

**Default-allow + deny-list.** The daemon has full bpftrace capability. Policy
does not grant access — it *removes* it. A probe runs unless a deny rule fires.

> ⚠️ The trust boundary is these files, not the binary. Anyone who can write them
> controls root-level kernel tracing on the host. Protect them accordingly
> (they are gated by the Teleport identity that launches the server).

## The two knobs

| Env var | Points at | Falls back to |
|---|---|---|
| `TRACESLEUTH_CATALOG` | `catalog.json` (this dir) — caps, high-frequency set, deny-lists | compiled `catalog.Default()` |
| `TRACESLEUTH_POLICY`  | `policy/policy.rego` — the deny rules | embedded copy of `policy.rego` |

Both are wired in the repo's `.mcp.json` launch command.

## catalog.json

A snapshot of the built-in catalog. The fields policy actually enforces:

- `high_frequency` is **derived** from each attach point's `high_frequency: true`
  flag — add a point with that flag to require aggregation for it.
- `denied_attach_points` / `denied_probe_types` — **the deny-list.** Empty by
  default (fully open). Add names here to forbid them:

  ```json
  "denied_attach_points": ["vfs_unlink", "signal_generate"],
  "denied_probe_types": ["uprobe"]
  ```

- `default_duration`, `max_duration`, `max_concurrent` — the modality limits.

`attach_points` is advertised by `list_probe_catalog` for discovery; under
default-allow it is **not** an allow-list — unlisted points still run unless
denied.

The committed `catalog.json` must stay a faithful copy of `catalog.Default()`
(a Go test enforces this). Customize a *deployed* copy, not the checked-in one,
or intentionally change both.

## policy.rego

The deny rules (explicit deny-lists + the modality guards). Edit
`policy/policy.rego`, keep `internal/policy/policy.rego` byte-identical (a test
guards it), and `opa test ./policy/...` must pass.
