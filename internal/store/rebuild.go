package store

import "tracesleuth/internal/event"

// Rebuild wipes the projection and replays events into it in order. This is the
// recovery path the whole design hinges on: if the index is lost or corrupted,
// the JSONL logs (the source of truth) reconstruct it exactly.
func (s *Store) Rebuild(events []event.Event) error {
	if err := s.Reset(); err != nil {
		return err
	}
	for _, e := range events {
		if err := s.Apply(e); err != nil {
			return err
		}
	}
	return nil
}
