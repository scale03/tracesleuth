package catalog

import (
	"reflect"
	"testing"
)

// TestStarterCatalogMatchesDefault guards the shipped, operator-editable starter
// (deploy/policy/catalog.json) against drift from the compiled Default(). The
// starter is meant to be a faithful, uncustomized snapshot people copy and edit;
// if Default() changes, regenerate the starter so the two agree.
func TestStarterCatalogMatchesDefault(t *testing.T) {
	got, err := Load("../../deploy/policy/catalog.json")
	if err != nil {
		t.Fatalf("load starter catalog: %v", err)
	}
	if !reflect.DeepEqual(got, Default()) {
		t.Fatalf("deploy/policy/catalog.json has drifted from catalog.Default() — regenerate it")
	}
}

// TestAsDataShape verifies the data document the Rego policy reads is well-formed:
// every key present, deny-lists non-nil (so Rego membership is defined), and the
// high-frequency set derived from the advertised points.
func TestAsDataShape(t *testing.T) {
	d := Default().AsData()
	for _, k := range []string{"high_frequency", "denied_attach_points", "denied_probe_types", "default_duration", "max_duration", "max_concurrent"} {
		if _, ok := d[k]; !ok {
			t.Fatalf("AsData missing key %q", k)
		}
	}
	if d["denied_attach_points"] == nil || d["denied_probe_types"] == nil {
		t.Fatal("deny-lists must be non-nil slices, not nil")
	}
	hf, ok := d["high_frequency"].([]string)
	if !ok || len(hf) == 0 {
		t.Fatalf("high_frequency should be a non-empty []string, got %#v", d["high_frequency"])
	}
}
