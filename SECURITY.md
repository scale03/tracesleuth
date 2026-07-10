# Security

## What TraceSleuth is

A daemon that runs operator/agent-supplied **bpftrace** programs against a Linux
kernel and records an auditable trail of every one. bpftrace runs eBPF as root,
so the trust boundary is: *untrusted script text in, kernel-level execution out.*
The security design is about constraining and recording that.

## Threat model

**In scope — what we defend against:**

| Threat | Mitigation |
|---|---|
| Untrusted / malicious script shape | `bpftrace --dry-run` parse check, then policy: probe-type & attach-point allow-list, duration cap, required aggregation on high-frequency points (`internal/policy`, `policy/*.rego`). |
| Output flooding / resource abuse via high-frequency probes | Aggregation required by policy; inline output byte-capped and summarized (`internal/output`); duration hard-capped and enforced by the executor, not the script. |
| Silent tampering with the audit record | Every log line is hash-chained (sha256 of prev hash + content) and seq-numbered; `verify-chain` detects any edit, deletion, insertion, or reorder. |
| Loss/corruption of the query index | SQLite is a disposable projection; the JSONL log is the source of truth and rebuilds it (`tracectl reindex`). |
| Privilege sprawl | Only bpftrace is elevated, via a sudoers rule scoped to that exact binary. The daemon itself does not run as root. |
| Unbounded continuous probes (baselines, Phase 7) | TTL mandatory and enforced twice — by policy at creation and by the daemon independently at runtime. |

**Out of scope — what we do NOT yet protect against (be explicit):**

- **Semantic safety of an allowed script.** Policy checks shape and attach point,
  not intent; an allow-listed probe can still be expensive. cgroup/CPU/memory
  guards are Phase 4 and not yet implemented.
- **Authentication / authorization of the caller.** Phase 1 identity is a CLI
  flag and is *not* verified. Cryptographic identity (Teleport certificates) is
  Phase 2. Do not expose the daemon on a network until then.
- **Multi-host / cross-host audit integrity.** Each host's log is independent;
  there is no central tamper-evident ledger yet.
- **Confidentiality of captured output.** Probe output may contain sensitive
  kernel/process data; it is stored unencrypted under the data directory. Protect
  that directory with filesystem permissions.

## The audit chain, precisely

Each JSONL line carries `seq` (0-based, contiguous) and
`hash = sha256(prev_hash || canonical_json_without_hash_field)`. Verification
walks the file checking seq contiguity, that each `prev_hash` matches the prior
line's `hash`, and that each stored `hash` recomputes. Any single-line edit,
removal, insertion, or reorder is detected and pinpointed. This is *tamper
evidence*, not tamper *prevention*: it proves a log was altered, it does not stop
someone with write access from replacing the whole file — cross-host anchoring of
head hashes is future work.

## Reporting a vulnerability

Email the maintainers listed in [`OWNERS`](OWNERS). Please do not open a public
issue for security-sensitive reports.
