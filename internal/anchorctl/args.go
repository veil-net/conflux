// Package anchorctl drives the embedded anchorctl binary.
//
// Everything conflux asks of an anchor goes through here, and the argv these
// functions build is the whole of conflux's contribution to how an anchor runs.
// That makes this the place a wrapper's bugs live -- a "-taint" for a "-taints", a
// boolean passed bare when it needed a value -- and none of them are visible in a
// diff. Hence the golden files beside the tests.
package anchorctl

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/veil-net/conflux/internal/config"
)

// StartMode is everything conflux decides about an anchor. What it does not decide
// -- the identity, the realm root, the credential, the bootstrap list -- arrives
// separately, in a manifest on stdin.
type StartMode struct {
	TUN     bool
	TUNName string
	IPv4    string
	Subnets []string
	Proxies []string
	Taints  []string
	Dir     string

	// Peers is the bootstrap list, or empty to let the manifest supply it.
	//
	// Empty means the flag is not passed at all, which is the whole point: anchorctl
	// takes bootstrap from the manifest only for fields no flag named, so omitting
	// -peers is what keeps the issuer's own list in play. Passing an empty -peers
	// would override it with nothing.
	Peers []string

	// Uplink is the link layer 1 runs over instead of a UDP socket, or empty for
	// the host's IP network. Orthogonal to every other field here: it decides the
	// medium, and the rest decide what this machine does with the realm on it.
	Uplink string

	// Port is the UDP port to bind on every interface, or zero for the kernel's
	// choice. Zero is not passed at all, for the reason -peers is not: the manifest
	// carries a listenPort and anchorctl takes it for any field no flag named.
	Port uint16

	// LowLatency carries layer-2 frames on QUIC datagrams. Passed only when true --
	// no manifest field describes it, so an omitted flag and an explicit false are
	// the same instruction, and omitting keeps the argv shorter.
	LowLatency bool

	// ServeExit and UseExit route the public internet out of and into the overlay.
	// Always passed, in both directions: the manifest does carry these two, and an
	// anchor that became an exit because a document said so is a surprise conflux
	// will not allow.
	ServeExit bool
	UseExit   bool
}

// ModeFromConfig reads the operator's intent into the shape Args needs.
func ModeFromConfig(c *config.Config, anchorDir string) StartMode {
	m := StartMode{
		TUN:     c.Mode == config.ModeTUN,
		Taints:  c.Taints,
		Dir:     anchorDir,
		Subnets: c.Subnets,
		Proxies: c.Proxies,
		IPv4:    c.IPv4,
		Uplink:  c.Uplink,
		Peers:   c.Peers,

		Port:       c.Port,
		LowLatency: c.LowLatency,
		ServeExit:  c.ServeExit,
		UseExit:    c.UseExit,
	}

	if m.TUN {
		m.TUNName = c.TUNInterface()
	}

	return m
}

// Args builds the `start` invocation, without the connection flags.
//
// Two rules, both deliberate and both load-bearing:
//
// Every mode-defining flag is passed, including the ones whose value is the
// default. anchorctl records which flags were typed with fs.Visit and lets a
// manifest supply the rest, so a flag conflux omits is a field the issuer decides.
// Passing -tun explicitly in both directions keeps the mode conflux's, whatever a
// future API build puts in the document.
//
// Booleans are written -flag=value and never bare. A bare -tun followed by a
// positional would be unambiguous to Go's flag package but not to anyone reading
// the argv in a log, and the =form costs nothing.
func (m StartMode) Args() []string {
	args := []string{"start", "-manifest", "-"}

	if m.Dir != "" {
		args = append(args, "-dir", m.Dir)
	}

	if len(m.Taints) > 0 {
		args = append(args, "-taints", strings.Join(m.Taints, ","))
	}

	// Only when set, unlike the mode flags above. This is the one field conflux
	// deliberately leaves to the manifest when the operator named nothing: the
	// issuer knows where its own realm answers, and a machine that hardcoded that
	// list would stop bootstrapping the day the API moved a node.
	if len(m.Peers) > 0 {
		args = append(args, "-peers", strings.Join(m.Peers, ","))
	}

	// Before -tun, because it is the medium the rest of this runs over. anchorctl
	// leaves -punch and -map-port off beside it as long as conflux does not type
	// them, and conflux never has: both mean nothing on a cable, and anchor refuses
	// the pair rather than ignoring it.
	if m.Uplink != "" {
		args = append(args, "-uplink", m.Uplink)
	}

	// Only when set, like -peers and for the same reason: the manifest carries a
	// listenPort, and a zero here means "no opinion" rather than "port zero".
	// Refused beside an uplink, which binds no socket -- Validate catches that.
	if m.Port != 0 {
		args = append(args, "-port", strconv.FormatUint(uint64(m.Port), 10))
	}

	// Only when true. No manifest field describes low latency, so anchorctl's own
	// default applies to an omitted flag and an explicit false says the same thing.
	if m.LowLatency {
		args = append(args, "-low-latency=true")
	}

	args = append(args, "-tun="+boolText(m.TUN))

	if m.TUN && m.TUNName != "" {
		args = append(args, "-tun-name", m.TUNName)
	}

	// Always both, in whichever direction, rather than leaving either to the
	// manifest: an anchor that silently became an internet exit because a document
	// said so would be a surprise of the worst kind. Off unless conflux was asked,
	// and TUN-only -- Validate refuses the pair with userspace mode.
	args = append(args, "-serve-exit="+boolText(m.ServeExit), "-use-exit="+boolText(m.UseExit))

	if m.IPv4 != "" {
		args = append(args, "-ipv4", m.IPv4)
	}

	if len(m.Subnets) > 0 {
		args = append(args, "-serve-subnets", strings.Join(m.Subnets, ","))
	}

	// -serve-proxy is repeatable rather than a list, so one flag per spec.
	for _, p := range m.Proxies {
		args = append(args, "-serve-proxy", p)
	}

	return args
}

// Validate catches the combinations anchor's own validate would refuse, here,
// where the message can name the conflux flag rather than the anchor field.
func (m StartMode) Validate() error {
	if m.TUN && len(m.Proxies) > 0 {
		return fmt.Errorf(
			"a reverse proxy needs userspace mode: with a host interface the kernel owns the overlay address, so bind it directly")
	}

	if !m.TUN {
		if len(m.Subnets) > 0 {
			return fmt.Errorf("forwarding a subnet needs a host interface to forward out of, which userspace mode has none of")
		}

		if m.IPv4 != "" {
			return fmt.Errorf("an overlay IPv4 needs a host interface to assign it to")
		}

		if m.ServeExit || m.UseExit {
			return fmt.Errorf("routing the public internet either way needs a host interface, which userspace mode has none of")
		}
	}

	if len(m.Taints) == 0 {
		return fmt.Errorf("no taints")
	}

	if m.Uplink != "" {
		if _, err := config.ParseUplinkSpec(m.Uplink); err != nil {
			return err
		}

		if m.Port != 0 {
			return fmt.Errorf("an uplink binds no socket, so there is no port to choose")
		}
	}

	return nil
}

// RenewArgs installs a renewed chain on the running anchor, without a restart.
//
// -inline makes anchorctl read the file and send the bytes, so the daemon never
// opens a path a caller named.
func RenewArgs(credPath string) []string {
	return []string{"renew", "-cred", credPath, "-inline"}
}

// StopArgs closes the anchor. The daemon stays up.
func StopArgs() []string { return []string{"stop"} }

// StatusArgs asks what is running.
func StatusArgs() []string { return []string{"status"} }

// MetricsArgs asks for the counters and gauges.
//
// conflux reads exactly one of them, anchor_connections, to tell a link that has
// ended from one that is merely quiet. status cannot answer that: an anchor on an
// uplink binds no socket, so it reports no underlay address and nothing else about
// the link either.
func MetricsArgs() []string { return []string{"metrics"} }

func boolText(v bool) string {
	if v {
		return "true"
	}

	return "false"
}
