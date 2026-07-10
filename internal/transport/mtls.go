package transport

import (
	"crypto/tls"
	"crypto/x509"
	"errors"

	"tracesleuth/internal/service"
)

// MTLSResolver derives identity from a verified TLS client certificate — the
// path a programmatic client using tbot's TLS output takes. Teleport (like most
// PKI) encodes the username in the certificate's Common Name (or a URI SAN) and
// the user's roles in the Subject Organization fields, so this reads exactly
// those. It assumes the TLS layer already verified the chain against the
// Teleport CA; it does not itself trust an unverified cert.
type MTLSResolver struct {
	peer []*x509.Certificate
}

// NewMTLSResolver builds a resolver from a completed TLS handshake. Pass the
// server-side *tls.ConnectionState; PeerCertificates[0] is the client leaf.
func NewMTLSResolver(state *tls.ConnectionState) *MTLSResolver {
	if state == nil {
		return &MTLSResolver{}
	}
	return &MTLSResolver{peer: state.PeerCertificates}
}

// NewMTLSResolverFromChain is the same but from an explicit verified chain
// (used in tests and by non-tls.Conn callers).
func NewMTLSResolverFromChain(certs []*x509.Certificate) *MTLSResolver {
	return &MTLSResolver{peer: certs}
}

func (r *MTLSResolver) Kind() string { return "mtls" }

func (r *MTLSResolver) Resolve() (service.Identity, error) {
	if len(r.peer) == 0 {
		return service.Identity{}, errors.New("no client certificate presented")
	}
	leaf := r.peer[0]

	name := leaf.Subject.CommonName
	if name == "" && len(leaf.URIs) > 0 {
		name = leaf.URIs[0].String() // SPIFFE-style identity URI
	}
	if name == "" {
		return service.Identity{}, errors.New("client certificate has no CommonName or URI SAN identity")
	}
	// Teleport carries roles in the Subject Organization. Copy defensively.
	roles := append([]string(nil), leaf.Subject.Organization...)
	return service.Identity{Name: "mtls:" + name, Roles: roles}, nil
}
