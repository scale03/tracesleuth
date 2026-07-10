// Package transport isolates identity extraction behind one interface so the
// daemon logic, policy input, and JSONL schema never need to know which channel
// produced the caller's identity. The plan calls for SSH (via tsh) and mTLS
// (via tbot's TLS output) to be supported at once — not SSH-now-mTLS-later — and
// both are issued by the same Teleport CA, so there is one root of trust and two
// resolvers reading two certificate formats.
//
//	SSH  — interactive/human use and simple agent setups (identity from the
//	       Teleport-brokered SSH session).
//	mTLS — programmatic clients wanting a direct connection without the SSH
//	       proxy (identity from a verified client certificate).
package transport

import "tracesleuth/internal/service"

// IdentityResolver turns a transport-specific connection into a verified caller
// identity. Each implementation is constructed per-connection with whatever that
// transport provides (SSH session env, TLS peer certificates), so Resolve itself
// needs no arguments.
type IdentityResolver interface {
	// Resolve returns the caller's identity and roles, or an error if the
	// connection carries no usable identity (which callers may treat as
	// "unauthenticated" rather than silently inventing one).
	Resolve() (service.Identity, error)
	// Kind names the transport ("ssh" or "mtls") for logging and audit.
	Kind() string
}
