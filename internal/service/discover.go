package service

import "context"

// defaultListLimit bounds a discovery page when the caller gives no limit — the
// kernel exposes thousands of probes, so a full dump is never the default.
const defaultListLimit = 100

// ProbeListing is one page of host probe discovery.
type ProbeListing struct {
	Filter string   // the glob applied ("*" if none)
	Total  int      // total matches before pagination
	Offset int      // index of the first returned probe
	Probes []string // this page, sorted
}

// HasMore reports whether probes remain past this page.
func (l ProbeListing) HasMore() bool { return l.Offset+len(l.Probes) < l.Total }

// ListKernelProbes enumerates the probes the host actually exposes (via the
// executor's `bpftrace -l`), narrowed by a bpftrace probe glob and paged. This
// is the second discovery tier — everything the kernel has — distinct from the
// curated catalog, and it enforces nothing: it attaches to no probe.
func (s *Service) ListKernelProbes(ctx context.Context, filter string, offset, limit int) (ProbeListing, error) {
	if filter == "" {
		filter = "*"
	}
	if limit <= 0 {
		limit = defaultListLimit
	}
	if offset < 0 {
		offset = 0
	}

	all, err := s.cfg.Executor.List(ctx, filter)
	if err != nil {
		return ProbeListing{}, err
	}
	total := len(all)

	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return ProbeListing{Filter: filter, Total: total, Offset: offset, Probes: all[offset:end]}, nil
}
