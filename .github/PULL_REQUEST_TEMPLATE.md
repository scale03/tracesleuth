<!--
Write this as an engineer, not an assistant. State what the code does and why.
No "as requested", no restating the issue, no marketing. See AGENT.md.
-->

## What changed

<!-- The change itself, in the present tense. -->

## Why

<!-- The one thing that isn't obvious from the diff. -->

## How it was verified

<!-- Commands run and what you observed. Not "tests pass" — which tests, against what. -->

## Checklist

- [ ] `go build ./... && go vet ./... && go test ./...` green
- [ ] `opa test ./policy/...` green and `opa fmt --list policy/` prints nothing
- [ ] Policy change? Paired tests in `policy/*_test.rego` **and**
      `internal/policy/policy_test.go`, and `internal/catalog` updated so
      advertised and enforced don't drift.
- [ ] New behaviour has a test that drives it.
- [ ] No new source of truth introduced (JSONL log stays authoritative).
