package config

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// MaxTaints and MaxTaintName mirror anchor's own limits (internal/realm/taint.go).
const (
	MaxTaints    = 32
	MaxTaintName = 64
)

// ValidateTaint applies anchor's rule and one of conflux's own.
//
// Anchor's: 1..64 bytes, and no byte at or below 0x20 or equal to 0x7f -- so no
// space and no control character. Conflux's addition is the comma, because the
// anchorctl flag is a comma-separated list and a taint containing one would
// silently become two compartments, which is the kind of mistake that presents as
// "nothing can reach me" a week later.
func ValidateTaint(name string) error {
	if name == "" {
		return fmt.Errorf("taint is empty")
	}

	if len(name) > MaxTaintName {
		return fmt.Errorf("taint %q is %d bytes and the limit is %d", name, len(name), MaxTaintName)
	}

	for i := range len(name) {
		switch {
		case name[i] == ',':
			return fmt.Errorf(
				"taint %q contains a comma, which would split it into two compartments; use --taint twice instead", name)
		case name[i] <= 0x20 || name[i] == 0x7f:
			return fmt.Errorf("taint %q contains a space or control character", name)
		}
	}

	return nil
}

// ProxySpec is one published service: an overlay port, a network, and the host
// address conflux's anchor dials when a connection arrives on it.
type ProxySpec struct {
	Port    int
	Network string // "tcp" or "udp"
	Backend string // host:port, dialled fresh per connection
}

// String renders the spec in the form anchorctl's -serve-proxy takes.
func (s ProxySpec) String() string {
	if s.Network == "tcp" {
		return fmt.Sprintf("%d=%s", s.Port, s.Backend)
	}

	return fmt.Sprintf("%d/%s=%s", s.Port, s.Network, s.Backend)
}

// ParseProxySpec reads OVERLAYPORT[/NETWORK]=BACKEND.
//
// Parsed here as well as in anchorctl deliberately: the same grammar checked twice
// is the difference between "conflux: 8080/tpc is not tcp or udp, at your shell"
// and a refusal from a daemon about a field the operator did not know they wrote.
// Cut on the first "=" so an IPv6 backend needs no escaping.
func ParseProxySpec(spec string) (ProxySpec, error) {
	key, value, ok := strings.Cut(spec, "=")
	if !ok {
		return ProxySpec{}, fmt.Errorf(
			"%q is not PORT[/NETWORK]=BACKEND, for example 8080=127.0.0.1:3000 or 53/udp=127.0.0.1:53", spec)
	}

	network := "tcp"

	if portText, netText, split := strings.Cut(strings.TrimSpace(key), "/"); split {
		key = strings.TrimSpace(portText)
		network = strings.ToLower(strings.TrimSpace(netText))

		if network != "tcp" && network != "udp" {
			return ProxySpec{}, fmt.Errorf("%q: %q is not tcp or udp", spec, network)
		}
	}

	port, err := strconv.Atoi(strings.TrimSpace(key))
	if err != nil || port < 1 || port > 65535 {
		return ProxySpec{}, fmt.Errorf("%q: %q is not an overlay port (1-65535)", spec, strings.TrimSpace(key))
	}

	backend := strings.TrimSpace(value)
	if backend == "" {
		return ProxySpec{}, fmt.Errorf("%q: no backend after the %q", spec, "=")
	}

	// SplitHostPort rather than a colon count, so "[::1]:5432" is one address and
	// not a parse accident. The backend is not resolved -- anchor dials it fresh
	// per connection, so a name that does not resolve yet is legitimate.
	if _, p, err := net.SplitHostPort(backend); err != nil {
		return ProxySpec{}, fmt.Errorf("%q: backend %q is not host:port: %w", spec, backend, err)
	} else if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
		return ProxySpec{}, fmt.Errorf("%q: backend %q has no usable port", spec, backend)
	}

	return ProxySpec{Port: port, Network: network, Backend: backend}, nil
}

// ParseOverlayIPv4 reads the operator-assigned overlay address.
//
// Anchor takes it as a prefix rather than a bare address, because the prefix length
// is what tells the stack which addresses are on-link. A bare "10.128.0.7" is the
// commonest mistake and gets its own message: it is not wrong so much as incomplete.
func ParseOverlayIPv4(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)

	p, err := netip.ParsePrefix(s)
	if err != nil {
		if addr, aerr := netip.ParseAddr(s); aerr == nil && addr.Is4() {
			return netip.Prefix{}, fmt.Errorf(
				"%s is an address without a prefix length: write it as %s/24", s, s)
		}

		return netip.Prefix{}, fmt.Errorf("%q is not an IPv4 address and prefix, for example 10.128.0.7/24", s)
	}

	if !p.Addr().Is4() {
		return netip.Prefix{}, fmt.Errorf("%s is IPv6: the overlay assigns its own v6 address, and this flag is for v4", s)
	}

	if p.Bits() < 8 || p.Bits() > 32 {
		return netip.Prefix{}, fmt.Errorf("%s has a prefix length of %d, which is outside 8-32", s, p.Bits())
	}

	if p.Addr() == p.Masked().Addr() && p.Bits() < 31 {
		return netip.Prefix{}, fmt.Errorf(
			"%s is the network address of its own prefix, not a host address: pick a host, for example %s/%d",
			s, p.Addr().Next(), p.Bits())
	}

	return p, nil
}
