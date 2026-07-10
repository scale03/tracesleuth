package event

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// canonicalBytes returns the deterministic serialization of an event with its
// own Hash field blanked. Because Event is a plain struct, encoding/json emits
// fields in declaration order, so this is stable without any extra
// canonicalization pass. The PrevHash field IS included in the content, so a
// reordering or substitution of any prior line changes every subsequent hash.
func canonicalBytes(e Event) ([]byte, error) {
	e.Hash = ""
	return json.Marshal(e)
}

// ComputeHash implements the chaining rule from the design:
//
//	hash = sha256( prev_hash + this line's own content )
//
// where "content" is the canonical serialization of the event with its Hash
// field empty. The genesis line uses prevHash == "" (JSON null on the wire is
// normalized to "" by the reader).
func ComputeHash(e Event) (string, error) {
	content, err := canonicalBytes(e)
	if err != nil {
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(e.PrevHash))
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// SHA256Hex is a convenience for hashing arbitrary blobs (script text, probe
// output) so callers don't reach for crypto/sha256 directly and risk drift.
func SHA256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// verifyHash recomputes the hash for a line and compares it to what was stored.
func verifyHash(e Event) error {
	want, err := ComputeHash(e)
	if err != nil {
		return err
	}
	if want != e.Hash {
		return fmt.Errorf("hash mismatch: stored=%s recomputed=%s", short(e.Hash), short(want))
	}
	return nil
}

func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12] + "…"
}
