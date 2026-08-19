package output

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// barWidth is the full-scale width, in cells, of a rendered aggregation bar.
const barWidth = 30

// mapLine matches a bpftrace colon-delimited aggregation line: "@name[key]: 12",
// "@[key]: 12", or "@name: 12". Histogram bucket lines ("[256, 512) 1042 |@@|")
// have no colon before their count, so they never match and pass through — the
// histogram is already a chart in bpftrace's own output.
var mapLine = regexp.MustCompile(`^@(\w*)(?:\[(.*)\])?:\s*(-?\d+(?:\.\d+)?)\s*$`)

// Aggregation is one bpftrace @map parsed from probe output.
type Aggregation struct {
	Name    string
	Entries []AggEntry
}

// AggEntry is a single key/value in a map (the key is "(scalar)" for a bare
// @name: value).
type AggEntry struct {
	Key   string
	Value float64
}

// parseAggregations extracts colon-delimited @maps from raw output, grouped by
// map name in first-seen order.
func parseAggregations(raw string) []Aggregation {
	var order []string
	byName := map[string][]AggEntry{}
	for _, ln := range strings.Split(raw, "\n") {
		m := mapLine.FindStringSubmatch(strings.TrimSpace(ln))
		if m == nil {
			continue
		}
		name := "@" + m[1]
		key := m[2]
		if key == "" {
			key = "(scalar)"
		}
		v, err := strconv.ParseFloat(m[3], 64)
		if err != nil {
			continue
		}
		if _, seen := byName[name]; !seen {
			order = append(order, name)
		}
		byName[name] = append(byName[name], AggEntry{Key: key, Value: v})
	}
	out := make([]Aggregation, 0, len(order))
	for _, name := range order {
		out = append(out, Aggregation{Name: name, Entries: byName[name]})
	}
	return out
}

// renderBars draws each aggregation as a horizontal bar chart, entries sorted by
// value descending and scaled to the map's own maximum. A non-zero value always
// gets at least one cell so it stays visible next to a much larger one.
func renderBars(aggs []Aggregation) string {
	var b strings.Builder
	for i, a := range aggs {
		if i > 0 {
			b.WriteByte('\n')
		}
		entries := append([]AggEntry(nil), a.Entries...)
		sort.SliceStable(entries, func(i, j int) bool { return entries[i].Value > entries[j].Value })

		var max float64
		keyW, valW := 0, 0
		for _, e := range entries {
			if e.Value > max {
				max = e.Value
			}
			if len(e.Key) > keyW {
				keyW = len(e.Key)
			}
			if w := len(formatVal(e.Value)); w > valW {
				valW = w
			}
		}
		fmt.Fprintf(&b, "%s (%d)\n", a.Name, len(entries))
		for _, e := range entries {
			cells := 0
			if max > 0 {
				cells = int(e.Value / max * barWidth)
			}
			if cells == 0 && e.Value > 0 {
				cells = 1
			}
			fmt.Fprintf(&b, "  %-*s  %*s  %s\n", keyW, e.Key, valW, formatVal(e.Value), strings.Repeat("█", cells))
		}
	}
	return b.String()
}

// formatVal prints integers without a decimal point and other values to two
// places, so bpftrace count/sum maps read as whole numbers.
func formatVal(v float64) string {
	if v == float64(int64(v)) {
		return strconv.FormatInt(int64(v), 10)
	}
	return strconv.FormatFloat(v, 'f', 2, 64)
}
