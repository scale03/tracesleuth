package policy

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/storage/inmem"
)

// embeddedPolicy is a byte-identical copy of /policy/policy.rego, compiled into
// the binary as the built-in fallback used when no external policy file is
// configured. TestEmbeddedPolicyMatchesSpec guards against drift.
//
//go:embed policy.rego
var embeddedPolicy string

// EmbeddedPolicy returns the built-in policy source.
func EmbeddedPolicy() string { return embeddedPolicy }

// Engine evaluates the Rego policy against a probe request. It is prepared once
// at startup (the module is compiled and the catalog data loaded into an
// in-memory store) and is safe for repeated Evaluate calls.
type Engine struct {
	query         rego.PreparedEvalQuery
	bundleVersion string
}

// NewEngine compiles the policy module and loads the catalog data document.
// If module is empty the embedded policy is used. data is injected as
// data.catalog — the caps, high-frequency set, and deny-lists the rules read.
func NewEngine(ctx context.Context, module string, data map[string]any, bundleVersion string) (*Engine, error) {
	if module == "" {
		module = embeddedPolicy
	}
	store := inmem.NewFromObject(map[string]any{"catalog": data})
	pq, err := rego.New(
		rego.Query("data.investigation"),
		rego.Module("policy.rego", module),
		rego.Store(store),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("compile policy: %w", err)
	}
	return &Engine{query: pq, bundleVersion: bundleVersion}, nil
}

// BundleVersion is the catalog/policy bundle this engine enforces.
func (e *Engine) BundleVersion() string { return e.bundleVersion }

// Evaluate runs the policy against one probe request and returns the Decision.
// It fails CLOSED: any evaluation error, or a malformed/absent decision, denies.
func (e *Engine) Evaluate(ctx context.Context, in Input) (Decision, error) {
	inputMap, err := toMap(in)
	if err != nil {
		return Decision{}, err
	}
	rs, err := e.query.Eval(ctx, rego.EvalInput(inputMap))
	if err != nil {
		return Decision{}, fmt.Errorf("evaluate policy: %w", err)
	}
	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return e.failClosed("policy produced no decision"), nil
	}
	doc, ok := rs[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return e.failClosed("policy decision malformed"), nil
	}
	d := Decision{Allow: false, BundleVersion: e.bundleVersion}
	if a, ok := doc["allow"].(bool); ok {
		d.Allow = a
	}
	if raw, ok := doc["deny"].([]any); ok {
		for _, m := range raw {
			if s, ok := m.(string); ok {
				d.Reasons = append(d.Reasons, s)
			}
		}
		sort.Strings(d.Reasons) // stable order for logs and tests
	}
	return d, nil
}

func (e *Engine) failClosed(reason string) Decision {
	return Decision{Allow: false, Reasons: []string{reason + " (failing closed)"}, BundleVersion: e.bundleVersion}
}

// toMap turns the typed Input into the generic document OPA evaluates against;
// the json tags on Input define the input.* field names the Rego reads.
func toMap(in Input) (map[string]any, error) {
	b, err := json.Marshal(in)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}
