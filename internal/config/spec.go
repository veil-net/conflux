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

// UplinkSpec names the link layer 1 runs over instead of a UDP socket.
//
// Two forms, and the split is exactly "is the device already open": a descriptor
// this machine's supervisor was handed, or a device conflux's anchor opens itself.
type UplinkSpec struct {
	// FD is the descriptor to adopt, or -1 when Path names the device instead.
	FD int

	// Path is the device to open. Empty when FD is set.
	Path string

	// Baud is the line speed to set, or zero to leave the line as it is.
	Baud int
}

// String renders the spec in the form anchorctl's -uplink takes, so a round trip
// through conflux.json gives back the same link.
func (s UplinkSpec) String() string {
	switch {
	case s.FD >= 0:
		return "fd:" + strconv.Itoa(s.FD)
	case s.Baud > 0:
		return s.Path + ":" + strconv.Itoa(s.Baud)
	default:
		return s.Path
	}
}

// ParseUplinkSpec reads fd:N, a device path, or a device path and a line speed.
//
// The grammar is anchor's (internal/uplink/spec.go) and is checked here as well for
// the same reason the proxy grammar is: a speed written where a device belongs
// should be refused at the shell that typed it, not by a daemon three layers down
// reporting on a field the operator never saw.
func ParseUplinkSpec(spec string) (UplinkSpec, error) {
	out := UplinkSpec{FD: -1}

	spec = strings.TrimSpace(spec)
	if spec == "" {
		return out, fmt.Errorf("an uplink needs a descriptor or a device, for example /dev/ttyUSB0:115200 or fd:3")
	}

	if rest, ok := strings.CutPrefix(spec, "fd:"); ok {
		fd, err := strconv.Atoi(rest)
		if err != nil || fd < 0 {
			return out, fmt.Errorf("%q: %q is not a descriptor", spec, rest)
		}

		out.FD = fd

		return out, nil
	}

	// A trailing ":digits" is a line speed. Split from the right, so a device whose
	// own path holds a colon still parses.
	if at := strings.LastIndex(spec, ":"); at >= 0 {
		if baud, err := strconv.Atoi(spec[at+1:]); err == nil {
			if baud <= 0 {
				return out, fmt.Errorf("%q: %d is not a line speed", spec, baud)
			}

			out.Path, out.Baud = spec[:at], baud

			if out.Path == "" {
				return out, fmt.Errorf("%q names a speed and no device", spec)
			}

			return out, nil
		}
	}

	out.Path = spec

	return out, nil
}

// SlowUplinkBaud is the line speed below which a realm handshake stops fitting
// inside anchor's sixty-second idle timeout.
//
// A full TLS 1.3 exchange with ML-DSA certificates in both directions, plus the
// post-handshake proof and the credential chain, is twenty to thirty kilobytes --
// about twenty-five seconds at 9600 baud, and longer than the timeout below it.
// Refusing would be wrong, since the number is a rate and not a limit, so this only
// decides whether conflux says something first.
const SlowUplinkBaud = 19200

// ValidatePeer applies anchor's bootstrap grammar, minus the resolving.
//
// Anchor's is discovery.ParseEntry: "host:port", or "anchorxxx@host:port" when the
// anchor expected to answer is known. Naming it is optional -- the realm gate and
// the certificate establish who answered regardless -- so it only buys an earlier
// error.
//
// What this deliberately does not do is resolve the name. Anchor resolves once,
// when it reads its configuration, and never again; doing it here as well would
// make `conflux up` fail on a machine whose resolver is not up yet, for a peer the
// anchor would have resolved perfectly well a second later. The shape is conflux's
// to check, the address is anchor's.
//
// The comma is refused for the same reason ValidateTaint refuses it: -peers is a
// comma-separated flag, so a comma inside one entry silently becomes two.
func ValidatePeer(entry string) error {
	if entry == "" {
		return fmt.Errorf("peer is empty")
	}

	if strings.Contains(entry, ",") {
		return fmt.Errorf(
			"peer %q contains a comma, which would split it into two entries; use --peers twice instead", entry)
	}

	rest := entry

	if at := strings.LastIndex(rest, "@"); at >= 0 {
		anchorID := rest[:at]
		if !strings.HasPrefix(anchorID, "anchor") {
			return fmt.Errorf(
				"peer %q names %q before the @, and an AnchorID starts with \"anchor\"", entry, anchorID)
		}

		rest = rest[at+1:]
	}

	host, port, err := net.SplitHostPort(rest)
	if err != nil {
		return fmt.Errorf("peer %q is not host:port, for example genesis.veilnet.com.au:4700", entry)
	}

	if host == "" {
		return fmt.Errorf("peer %q names a port and no host", entry)
	}

	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("peer %q: %q is not a port", entry, port)
	}

	return nil
}

// ValidatePeers checks a whole bootstrap list and refuses a duplicate.
//
// A repeated entry is not harmful to anchor, which dedupes on the address it
// resolves to, but it is always a mistake in something an operator typed.
func ValidatePeers(peers []string) error {
	seen := make(map[string]bool, len(peers))

	for _, p := range peers {
		if err := ValidatePeer(p); err != nil {
			return err
		}

		if seen[p] {
			return fmt.Errorf("peer %q is named twice", p)
		}

		seen[p] = true
	}

	return nil
}
