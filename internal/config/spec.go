package config

import (
	"encoding/base32"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// MaxTaints and MaxTaintName mirror anchor's own limits (internal/realm/taint.go).
const (
	MaxTaints    = 32
	MaxTaintName = 64
)

// ValidateTaint applies anchor's rule and one of conflux's own.
//
// Anchor's: 1..64 bytes of UTF-8 in which every character prints and none is a space,
// in any script -- a no-break or zero-width space hides as well as an ASCII one -- and
// neither '@' nor '+', which bind a served network to compartments (SPEC@a+b). The API
// refuses the same names. Conflux's addition is the comma: `--taint a,b` reads as two
// compartments and would be asked for as one named "a,b", and a subnet binding naming
// it could not be written inside the comma-separated -serve-subnets.
func ValidateTaint(name string) error {
	if name == "" {
		return fmt.Errorf("taint is empty")
	}

	if len(name) > MaxTaintName {
		return fmt.Errorf("taint %q is %d bytes and the limit is %d", name, len(name), MaxTaintName)
	}

	if !utf8.ValidString(name) {
		return fmt.Errorf("taint %q is not UTF-8", name)
	}

	for _, r := range name {
		switch {
		case r == ',':
			return fmt.Errorf(
				"taint %q contains a comma; for two compartments, use --taint twice", name)
		case r == '@' || r == '+':
			return fmt.Errorf("taint %q has %q, which binds a served network to compartments (SUBNET@a+b)", name, r)
		case unicode.IsSpace(r) || !unicode.IsGraphic(r):
			return fmt.Errorf("taint %q has a space or a character that does not print, %U", name, r)
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

// translatePool is anchor's DefaultTranslatePool, where it answers the IPv4 peers it
// translates for. An anchor refuses to send from inside it, which anchor's own Validate
// does not catch and its New does, at every start.
var translatePool = netip.MustParsePrefix("198.18.0.0/15")

// ParseOverlayIPv4 reads this machine's IPv4 the way anchord does: an address, which
// is a /32, or an address and the length of the range routed into the tunnel.
//
// Any unicast address a host could send from, another anchor's included: it never
// reaches the overlay, which carries everything translated into IPv6 from the
// identity's own address (anchor's docs/ipv4.md). Refused are the ones anchor refuses
// -- not IPv4, not unicast, a /0 that would route the whole IPv4 internet into the
// tunnel, or an address inside the translation pool.
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
	case translatePool.Contains(p.Addr()):
		return netip.Prefix{}, fmt.Errorf(
			"%s is inside %s, where anchor answers the IPv4 peers it translates for, and it will not send from there", s, translatePool)
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
// anchor expected to answer is known. Naming it is optional -- the handshake
// establishes who answered regardless -- and what it buys is that some other anchor
// listening at that address says nothing.
//
// Anchor skips an entry it cannot parse, with a warning nobody at the terminal sees;
// refusing it here is conflux's choice, because a bootstrap list that silently lost an
// entry is a machine that silently fails to join.
//
// What this deliberately does not do is resolve the name. Anchor resolves it again at
// the start of every bootstrap round; doing it here as well would make `conflux up`
// fail on a machine whose resolver is not up yet, for a peer the anchor would resolve
// perfectly well a round later. The shape is conflux's to check, the address is
// anchor's.
//
// The comma is refused because -peers is a comma-separated flag, so a comma inside
// one entry silently becomes two.
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

// ValidateAnchorID accepts exactly what anchor's id.Parse does, case included: one
// spelling per identifier, so a last character setting bits past the 256 the payload
// holds -- which the decoder alone ignores -- is refused.
func ValidateAnchorID(s string) error {
	if len(s) != len(anchorIDPrefix)+anchorIDEncoding.EncodedLen(32) ||
		!strings.EqualFold(s[:len(anchorIDPrefix)], anchorIDPrefix) {
		return fmt.Errorf("%q is not an AnchorID, which is \"anchor\" and 52 base32 characters", s)
	}

	payload := strings.ToLower(s[len(anchorIDPrefix):])

	if b, err := anchorIDEncoding.DecodeString(payload); err != nil || len(b) != 32 || anchorIDEncoding.EncodeToString(b) != payload {
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

// Anchor's bounds on a served list (internal/proto): as many entries as one route
// advertisement holds networks, an entry no longer than any name, and no more
// compartments bound across the list than one advertisement names.
const (
	MaxSubnetEntries = 64
	MaxSubnetEntry   = 255
	MaxBoundTaints   = 16
)

// AllSubnets is the entry that serves every private network the host is attached to,
// on every interface (anchor's hostnet.AllNetworks).
const AllSubnets = "*"

// splitBinding reads an entry as what it serves and the compartments it is bound to:
// SPEC, or SPEC@a+b. names is nil for an entry bound to none. The last '@' is the one,
// as in anchor, since a taint holds neither '@' nor '+'.
func splitBinding(entry string) (spec string, names []string) {
	i := strings.LastIndexByte(entry, '@')
	if i < 0 {
		return entry, nil
	}

	return entry[:i], strings.Split(entry[i+1:], "+")
}

// ValidateSubnet refuses the entries anchor refuses without looking at the host.
//
// An entry is an interface name, which anchor expands to every private network on
// it; a prefix, which must match an attached private network exactly; or *, every
// private network on every interface. Any of them may be bound to some of this
// machine's compartments as SPEC@a+b, so that only peers in those compartments reach
// it. Whether a network is attached is the host's to answer and anchor's to check at
// start; what can be answered here is a prefix with host bits set, which anchor
// refuses as the off-by-one it is, and one that can never be attached as written:
// outside every private range, or an IPv4 network spelled as IPv6, since anchor finds
// the host's IPv4 networks as IPv4 and compares the entry as it is.
//
// A comma is refused, since -serve-subnets is a comma-separated flag, and so is a
// slash outside a prefix, since no interface name holds one. Whether a binding names
// this machine's own compartments is ValidateSubnets', which knows them.
func ValidateSubnet(entry string) error {
	if strings.Contains(entry, ",") {
		return fmt.Errorf(
			"subnet %q contains a comma, which would split it into two entries; use --subnet twice instead", entry)
	}

	if len(entry) > MaxSubnetEntry {
		return fmt.Errorf("subnet %q is %d bytes and anchor allows %d", entry, len(entry), MaxSubnetEntry)
	}

	spec, names := splitBinding(entry)

	if names != nil {
		if strings.TrimSpace(spec) == "" {
			return fmt.Errorf("subnet %q binds nothing: write the network or interface before the @", entry)
		}

		for _, n := range names {
			if err := ValidateTaint(n); err != nil {
				return fmt.Errorf("subnet %q: %w", entry, err)
			}
		}
	}

	spec = strings.TrimSpace(spec)
	if spec == AllSubnets {
		return nil
	}

	p, err := netip.ParsePrefix(spec)
	if err != nil {
		if strings.Contains(spec, "/") {
			return fmt.Errorf("subnet %q is neither a prefix nor an interface name: %v", entry, err)
		}

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

// ValidateSubnets checks a whole served list: each entry, anchor's bounds on the
// list, and that every binding names compartments this machine is in -- anchor
// refuses a network bound to a compartment the anchor is not configured in
// (ErrSubnetTaints) before anything is built. A machine in its realm's default
// compartment has no name to bind to, so it binds nothing.
func ValidateSubnets(entries, taints []string) error {
	if len(entries) > MaxSubnetEntries {
		return fmt.Errorf("%d subnets, and anchor serves at most %d", len(entries), MaxSubnetEntries)
	}

	bound := map[string]bool{}

	for _, e := range entries {
		if err := ValidateSubnet(e); err != nil {
			return err
		}

		_, names := splitBinding(e)

		for _, n := range names {
			if !slices.Contains(taints, n) {
				return fmt.Errorf(
					"subnet %q is bound to %q, which this machine is not in; its taints are %s",
					e, n, describeTaints(taints))
			}

			bound[n] = true
		}
	}

	if len(bound) > MaxBoundTaints {
		return fmt.Errorf("subnets are bound to %d compartments, and anchor allows %d", len(bound), MaxBoundTaints)
	}

	return nil
}

func describeTaints(taints []string) string {
	if len(taints) == 0 {
		return "none (the realm's default compartment)"
	}

	return strings.Join(taints, ", ")
}
