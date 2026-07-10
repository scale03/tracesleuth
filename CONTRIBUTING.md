# Contributing

## Commits

[Conventional Commits](https://www.conventionalcommits.org/): `type(scope):
short imperative subject`. No body unless the "why" isn't obvious from the diff.
Types: `feat`, `fix`, `docs`, `test`, `refactor`, `perf`, `chore`, `ci`,
`build`. One logical change per commit — the log should read like a changelog.

Example: `feat(policy): deny unaggregated probes on high-frequency attach points`

## Before you push

```sh
go build ./...
go test ./...
go vet ./...
opa test ./policy/...
opa fmt --list policy/   # must print nothing
```

## Policy changes are safety-critical

`internal/policy` (the runtime engine) and `policy/*.rego` (the reviewable spec)
enforce the same rules and **must stay in sync**. Any change to one requires the
matching change to the other, and:

> **Every new or changed policy rule needs a paired test — in both
> `policy/*_test.rego` and `internal/policy/policy_test.go` — in the same PR.**
> This is the one place test coverage has direct safety consequences.

If you add an allowed probe type or attach point, update
`internal/catalog` (the single source `list_probe_catalog` and both policy
implementations read from) so advertised and enforced never drift.

## Tests

- Unit tests are colocated with the code they cover.
- The end-to-end tests in `internal/service` use the mock executor, so they run
  anywhere without root or a kernel.
- Real-bpftrace integration tests belong behind a separate, privileged CI job
  (Linux kernel + root), so the default `go test ./...` stays fast and
  unprivileged.
