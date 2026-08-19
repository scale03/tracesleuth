package service

import (
	"context"
	"testing"
)

func TestListKernelProbesPaginates(t *testing.T) {
	s, _ := newSvc(t) // mock executor: 10 probes
	ctx := context.Background()

	first, err := s.ListKernelProbes(ctx, "*", 0, 4)
	if err != nil {
		t.Fatal(err)
	}
	if first.Total != 10 || len(first.Probes) != 4 || first.Offset != 0 {
		t.Fatalf("first page wrong: %+v", first)
	}
	if !first.HasMore() {
		t.Fatal("expected more after the first page")
	}

	// Second page continues where the first ended, no overlap.
	second, _ := s.ListKernelProbes(ctx, "*", 4, 4)
	if second.Probes[0] == first.Probes[0] {
		t.Fatal("second page overlaps the first")
	}

	// Last page returns the remainder and reports no more.
	last, _ := s.ListKernelProbes(ctx, "*", 8, 4)
	if len(last.Probes) != 2 || last.HasMore() {
		t.Fatalf("last page wrong: %+v", last)
	}
}

func TestListKernelProbesFilter(t *testing.T) {
	s, _ := newSvc(t)
	got, err := s.ListKernelProbes(context.Background(), "tracepoint:*", 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	if got.Total == 0 || got.Total == 10 {
		t.Fatalf("filter did not narrow: total=%d", got.Total)
	}
	if got.Filter != "tracepoint:*" {
		t.Fatalf("filter not echoed: %q", got.Filter)
	}
}

// An offset past the end yields an empty page, not an error or a panic.
func TestListKernelProbesOffsetPastEnd(t *testing.T) {
	s, _ := newSvc(t)
	got, err := s.ListKernelProbes(context.Background(), "*", 1000, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Probes) != 0 || got.HasMore() {
		t.Fatalf("offset past end should be empty and final: %+v", got)
	}
}

// A zero limit falls back to the default page size rather than returning nothing.
func TestListKernelProbesDefaultLimit(t *testing.T) {
	s, _ := newSvc(t)
	got, _ := s.ListKernelProbes(context.Background(), "*", 0, 0)
	if len(got.Probes) != got.Total { // 10 < defaultListLimit, so all fit
		t.Fatalf("zero limit should use the default and return all 10: %+v", got)
	}
}
