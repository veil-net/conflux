package config

import (
	"encoding/base32"
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

// ValidateTaints checks a whole set against anchor's ceiling as well as each name.
//
// A repeated name is not refused: anchor derives one tag per name and collapses
// duplicates, so a set that names one compartment twice names it once.
func ValidateTaints(names []string) error {
	if len(names) > MaxTaints {
		return fmt.Errorf("%d taints, and anchor allows %d", len(names), MaxTaints)
	}

	for _, t := range names {
		if err := ValidateTaint(t); err != nil {
			return err
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
	// not a parse accident, and nothing further: anchor dials the backend fresh per
	// connection, so a name that does not resolve yet, or a named port, is legitimate.
	if _, _, err := net.SplitHostPort(backend); err != nil {
		return ProxySpec{}, fmt.Errorf("%q: backend %q is not host:port: %w", spec, backend, err)
	}

	return ProxySpec{Port: port, Network: network, Backend: backend}, nil
}

// ValidateProxies parses every spec and refuses a repeated overlay port and network,
// which anchor refuses at start when the second listener finds the port taken.
func ValidateProxies(specs []string) ([]ProxySpec, error) {
	out := make([]ProxySpec, 0, len(specs))
	seen := make(map[string]bool, len(specs))

	for _, s := range specs {
		spec, err := ParseProxySpec(s)
		if err != nil {
			return nil, err
		}

		key := strconv.Itoa(spec.Port) + "/" + spec.Network
		if seen[key] {
			return nil, fmt.Errorf("overlay port %s is given twice", key)
		}

		seen[key] = true

		out = append(out, spec)
	}

	return out, nil
}

// ParseOverlayIPv4 reads this machine's IPv4 the way anchord does: an address, which
// is a /32, or an address and the length of the range routed into the tunnel.
//
// Any unicast address a host could send from, another anchor's included: it never
// reaches the overlay, which carries everything translated into IPv6 from the
// identity's own address (anchor's docs/ipv4.md). Refused are the ones anchor refuses
// -- not IPv4, not unicast, or a /0 that would route the whole IPv4 internet into
// the tunnel.
func ParseOverlayIPv4(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		addr, aerr := netip.ParseAddr(s)
		if aerr != nil || !addr.Is4() {
			return netip.Prefix{}, fmt.Errorf(
				"%q is not an IPv4 address or prefix, for example 10.128.0.7 or 10.128.0.7/24", s)
		}

		p = netip.PrefixFrom(addr, 32)
	}

	switch {
	case !p.Addr().Is4():
		return netip.Prefix{}, fmt.Errorf("%s is IPv6: the overlay derives this machine's IPv6 from its identity, and this is for IPv4", s)
	case !p.Addr().IsGlobalUnicast():
		return netip.Prefix{}, fmt.Errorf(
			"%s is not a unicast address a host sends from: loopback, link-local, multicast and broadcast are refused", s)
	case p.Bits() == 0:
		return netip.Prefix{}, fmt.Errorf("%s would route the whole IPv4 internet into the tunnel, which is what --use-exit is for", s)
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
		if err := ValidateAnchorID(rest[:at]); err != nil {
			return fmt.Errorf("peer %q: %w", entry, err)
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

	// The way netip reads a port once anchor has resolved the host: decimal, 16 bits.
	if _, err := strconv.ParseUint(port, 10, 16); err != nil {
		return fmt.Errorf("peer %q: %q is not a port", entry, port)
	}

	return nil
}

// ValidatePeers checks a whole bootstrap list. A repeated entry is not refused:
// anchor dials each address once however many times it is named.
func ValidatePeers(peers []string) error {
	for _, p := range peers {
		if err := ValidatePeer(p); err != nil {
			return err
		}
	}

	return nil
}

// anchorIDPrefix and anchorIDEncoding are how anchor spells an AnchorID
// (internal/id): the prefix, then 32 bytes in unpadded lower-case base32.
const anchorIDPrefix = "anchor"

var anchorIDEncoding = base32.NewEncoding("abcdefghijklmnopqrstuvwxyz234567").WithPadding(base32.NoPadding)

// ValidateAnchorID accepts exactly what anchor's id.Parse does, case included.
func ValidateAnchorID(s string) error {
	if len(s) != len(anchorIDPrefix)+anchorIDEncoding.EncodedLen(32) ||
		!strings.EqualFold(s[:len(anchorIDPrefix)], anchorIDPrefix) {
		return fmt.Errorf("%q is not an AnchorID, which is \"anchor\" and 52 base32 characters", s)
	}

	if b, err := anchorIDEncoding.DecodeString(strings.ToLower(s[len(anchorIDPrefix):])); err != nil || len(b) != 32 {
		return fmt.Errorf("%q is not an AnchorID, which is \"anchor\" and 52 base32 characters", s)
	}

	return nil
}

// privateNetworks is anchor's list of what a subnet router may offer
// (internal/hostnet): RFC 1918, carrier-grade NAT, and unique local IPv6.
var privateNetworks = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fc00::/7"),
}

// ValidateSubnet refuses the entries anchor refuses without looking at the host.
//
// An entry is an interface name, which anchor expands to every private network on
// it, or a prefix, which must match an attached private network exactly. Whether it
// is attached is the host's to answer and anchor's to check at start; what can be
// answered here is a prefix with host bits set, which anchor refuses as the
// off-by-one it is, and one that can never be attached as written: outside every
// private range, or an IPv4 network spelled as IPv6, since anchor finds the host's
// IPv4 networks as IPv4 and compares the entry as it is.
func ValidateSubnet(entry string) error {
	p, err := netip.ParsePrefix(strings.TrimSpace(entry))
	if err != nil {
		return nil // an interface name
	}

	if masked := p.Masked(); masked != p {
		return fmt.Errorf("subnet %s has host bits set; did you mean %s", entry, masked)
	}

	if a := p.Addr(); a.Is4In6() {
		if p.Bits() < 96 {
			return fmt.Errorf("subnet %s is not a private network", entry)
		}

		return fmt.Errorf("subnet %s is an IPv4 network written as IPv6, which anchor never finds attached; write %s",
			entry, netip.PrefixFrom(a.Unmap(), p.Bits()-96))
	}

	for _, r := range privateNetworks {
		if r.Bits() <= p.Bits() && r.Contains(p.Addr()) {
			return nil
		}
	}

	return fmt.Errorf(
		"subnet %s is not a private network: anchor forwards private networks only, and reaching the public internet through an anchor is what an exit is for",
		entry)
}
