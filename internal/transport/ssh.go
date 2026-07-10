package transport

import (
	"errors"
	"strings"

	"tracesleuth/internal/service"
)

// SSHResolver derives identity from the SSH session the server is running
// inside. When the MCP server is launched over `ssh` or `tsh ssh`, it executes
// on the target host with the session environment set. Under Teleport, the
// authenticated Teleport username is the login principal, and Teleport can
// export the user's roles into the session; a plain OpenSSH session falls back
// to the login user. It refuses to resolve outside an SSH session so it can
// never fabricate an identity for a local process.
type SSHResolver struct {
	getenv func(string) string
}

// NewSSHResolver builds a resolver over an environment lookup (os.Getenv in
// production; a map in tests).
func NewSSHResolver(getenv func(string) string) *SSHResolver {
	return &SSHResolver{getenv: getenv}
}

func (r *SSHResolver) Kind() string { return "ssh" }

func (r *SSHResolver) Resolve() (service.Identity, error) {
	// Evidence we are actually inside an SSH session.
	if r.getenv("SSH_CONNECTION") == "" && r.getenv("SSH_CLIENT") == "" {
		return service.Identity{}, errors.New("not an SSH session (no SSH_CONNECTION/SSH_CLIENT)")
	}
	// Prefer the Teleport-provided identity when present (Teleport can export
	// TELEPORT_USER / a roles list into the session), else the login user which,
	// under a Teleport-brokered login, is the cryptographically enforced
	// certificate principal.
	name := firstNonEmpty(r.getenv("TELEPORT_USER"), r.getenv("USER"), r.getenv("LOGNAME"))
	if name == "" {
		return service.Identity{}, errors.New("SSH session has no resolvable user")
	}
	roles := splitList(firstNonEmpty(r.getenv("TELEPORT_ROLES"), r.getenv("SSH_TELEPORT_ROLES")))
	return service.Identity{Name: "ssh:" + name, Roles: roles}, nil
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func splitList(s string) []string {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parts := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' })
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
