package transport

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestSSHResolverFromTeleportEnv(t *testing.T) {
	env := map[string]string{
		"SSH_CONNECTION": "10.0.0.5 51000 10.0.0.9 22",
		"TELEPORT_USER":  "agent-x",
		"TELEPORT_ROLES": "reliability-team,oncall",
		"USER":           "ale",
	}
	id, err := NewSSHResolver(func(k string) string { return env[k] }).Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if id.Name != "ssh:agent-x" {
		t.Fatalf("expected teleport user to win, got %q", id.Name)
	}
	if len(id.Roles) != 2 || id.Roles[0] != "reliability-team" {
		t.Fatalf("roles not parsed: %v", id.Roles)
	}
}

func TestSSHResolverFallsBackToLoginUser(t *testing.T) {
	env := map[string]string{"SSH_CLIENT": "10.0.0.5 51000 22", "USER": "ale"}
	id, err := NewSSHResolver(func(k string) string { return env[k] }).Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if id.Name != "ssh:ale" {
		t.Fatalf("expected login user fallback, got %q", id.Name)
	}
}

func TestSSHResolverRefusesNonSSH(t *testing.T) {
	env := map[string]string{"USER": "ale"} // no SSH_* → not an SSH session
	if _, err := NewSSHResolver(func(k string) string { return env[k] }).Resolve(); err == nil {
		t.Fatal("expected error outside an SSH session")
	}
}

func TestMTLSResolverExtractsIdentityAndRoles(t *testing.T) {
	cert := makeClientCert(t, "agent-x", []string{"reliability-team", "oncall"})
	id, err := NewMTLSResolverFromChain([]*x509.Certificate{cert}).Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if id.Name != "mtls:agent-x" {
		t.Fatalf("expected CN identity, got %q", id.Name)
	}
	// x509 encodes Organization as a SET OF, which DER-sorts, so assert on
	// membership rather than order.
	if len(id.Roles) != 2 || !hasRole(id.Roles, "oncall") || !hasRole(id.Roles, "reliability-team") {
		t.Fatalf("expected both roles from cert Organization, got %v", id.Roles)
	}
}

func TestMTLSResolverRequiresCert(t *testing.T) {
	if _, err := NewMTLSResolverFromChain(nil).Resolve(); err == nil {
		t.Fatal("expected error when no client cert is presented")
	}
}

func hasRole(roles []string, want string) bool {
	for _, r := range roles {
		if r == want {
			return true
		}
	}
	return false
}

// makeClientCert builds a self-signed leaf with the identity in CN and roles in
// the Subject Organization — the same encoding Teleport uses.
func makeClientCert(t *testing.T, cn string, roles []string) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn, Organization: roles},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
