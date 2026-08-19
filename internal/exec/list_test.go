package exec

import (
	"context"
	"strings"
	"testing"
)

func TestMockList(t *testing.T) {
	m := NewMock()
	all, _ := m.List(context.Background(), "")
	if len(all) == 0 {
		t.Fatal("empty filter should return the whole set")
	}

	tps, _ := m.List(context.Background(), "tracepoint:*")
	if len(tps) == 0 {
		t.Fatal("tracepoint:* matched nothing")
	}
	for _, p := range tps {
		if !strings.HasPrefix(p, "tracepoint:") {
			t.Errorf("tracepoint:* returned a non-tracepoint: %q", p)
		}
	}
	if len(tps) >= len(all) {
		t.Fatal("a filter should narrow the set")
	}

	tcp, _ := m.List(context.Background(), "kprobe:tcp*")
	if len(tcp) == 0 {
		t.Fatal("kprobe:tcp* matched nothing")
	}
	for _, p := range tcp {
		if !strings.HasPrefix(p, "kprobe:tcp") {
			t.Errorf("kprobe:tcp* returned %q", p)
		}
	}
}
