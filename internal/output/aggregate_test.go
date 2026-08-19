package output

import (
	"strings"
	"testing"
)

const mixedOutput = `Attaching probe(s)...

@latency_ns:
[256, 512)        1042 |@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@|
[512, 1K)          318 |@@@@@@@@@                       |

@count[nginx]: 1437
@count[node]: 402
@bytes: 8192
`

func TestParseAggregationsGroupsByMap(t *testing.T) {
	aggs := parseAggregations(mixedOutput)
	got := map[string]int{}
	for _, a := range aggs {
		got[a.Name] = len(a.Entries)
	}
	if got["@count"] != 2 {
		t.Errorf("@count: want 2 entries, got %d", got["@count"])
	}
	if got["@bytes"] != 1 {
		t.Errorf("@bytes: want 1 scalar entry, got %d", got["@bytes"])
	}
	// The histogram header/buckets have no colon-before-value, so they must not be
	// parsed as a map.
	if _, ok := got["@latency_ns"]; ok {
		t.Error("histogram was parsed as a colon-delimited map")
	}
}

func TestScalarKey(t *testing.T) {
	aggs := parseAggregations("@bytes: 8192\n")
	if len(aggs) != 1 || len(aggs[0].Entries) != 1 || aggs[0].Entries[0].Key != "(scalar)" {
		t.Fatalf("unexpected scalar parse: %+v", aggs)
	}
	if aggs[0].Entries[0].Value != 8192 {
		t.Fatalf("want value 8192, got %v", aggs[0].Entries[0].Value)
	}
}

func TestRenderBarsSortsDescendingAndScales(t *testing.T) {
	chart := renderBars(parseAggregations("@count[node]: 402\n@count[nginx]: 1437\n"))
	lines := strings.Split(strings.TrimRight(chart, "\n"), "\n")
	// Header then two rows.
	if len(lines) != 3 {
		t.Fatalf("want 3 lines, got %d:\n%s", len(lines), chart)
	}
	if !strings.Contains(lines[1], "nginx") {
		t.Errorf("largest value should sort first, got %q", lines[1])
	}
	// The max entry fills the full bar; the smaller one is strictly shorter.
	nginxBar := strings.Count(lines[1], "█")
	nodeBar := strings.Count(lines[2], "█")
	if nginxBar != barWidth {
		t.Errorf("max entry should fill %d cells, got %d", barWidth, nginxBar)
	}
	if nodeBar >= nginxBar || nodeBar == 0 {
		t.Errorf("smaller entry bar should be shorter but visible, got %d vs %d", nodeBar, nginxBar)
	}
}

// A non-zero value that rounds to zero cells still gets one, so it is never
// rendered as an empty bar next to a huge one.
func TestRenderBarsKeepsTinyValuesVisible(t *testing.T) {
	chart := renderBars(parseAggregations("@count[big]: 100000\n@count[tiny]: 1\n"))
	for _, ln := range strings.Split(chart, "\n") {
		if strings.Contains(ln, "tiny") && strings.Count(ln, "█") == 0 {
			t.Fatalf("tiny non-zero value rendered with no bar: %q", ln)
		}
	}
}

func TestSummaryChartEmptyForRawStream(t *testing.T) {
	s := Summarize([]byte("48000    nginx    tcp_connect\n48001    nginx    tcp_connect\n"))
	if s.Chart() != "" {
		t.Fatalf("a per-event stream has no @maps, want empty chart, got:\n%s", s.Chart())
	}
}

func TestFormatValIntegerVsFloat(t *testing.T) {
	if got := formatVal(1437); got != "1437" {
		t.Errorf("integer value: want 1437, got %q", got)
	}
	if got := formatVal(3.5); got != "3.50" {
		t.Errorf("float value: want 3.50, got %q", got)
	}
}
