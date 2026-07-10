package output

import (
	"strings"
	"testing"
)

func TestShortOutputKeptWhole(t *testing.T) {
	raw := []byte("@count[nginx]: 1437\n@count[node]: 402\n")
	s := Summarize(raw)
	if s.Truncated {
		t.Fatal("short aggregated output should not be truncated")
	}
	if !strings.Contains(s.Text, "nginx") {
		t.Fatal("expected content preserved")
	}
}

func TestLongStreamHeadTailTruncated(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 500; i++ {
		b.WriteString("event line ")
		b.WriteByte(byte('a' + i%26))
		b.WriteByte('\n')
	}
	s := Summarize([]byte(b.String()))
	if !s.Truncated {
		t.Fatal("expected long stream to be truncated")
	}
	if !strings.Contains(s.Text, "lines omitted") {
		t.Fatal("expected an explicit omitted-lines note")
	}
	if len(s.Text) >= s.RawBytes {
		t.Fatal("summary should be smaller than raw")
	}
}

func TestByteCapEnforced(t *testing.T) {
	// One giant single line (no newlines) must still be capped.
	raw := make([]byte, MaxInlineBytes*2)
	for i := range raw {
		raw[i] = 'x'
	}
	s := Summarize(raw)
	if !s.Truncated {
		t.Fatal("expected byte-cap truncation")
	}
	if len(s.Text) > MaxInlineBytes+200 {
		t.Fatalf("inline text exceeded cap: %d", len(s.Text))
	}
}
