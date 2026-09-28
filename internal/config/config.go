// Package config is what conflux keeps on disk.
//
// Three files, three lifetimes, deliberately not one:
//
//   - conflux.json  what the operator asked for. Written by up and proxy.
//   - state.json    what conflux derived. Written by the supervisor.
//   - manifest.b64  the identity. Written once, at enrolment, and never replaced
//     except to splice in a renewed chain.
//
// Splitting Config from State is not tidiness. The renewer rewrites NotAfter at
// every renewal from the supervisor, and a CLI rewrites Taints from a terminal; one file
// would make those a lost update. Splitting the manifest out again is because it is
// the only file with no second copy anywhere in the world.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/veil-net/conflux/internal/paths"
)

// Mode is which of anchor's two shapes this machine runs. They are mutually
// exclusive in anchor itself, not merely in conflux: a config carrying both a host
// interface and a reverse proxy is refused by anchor.Config.validate before
// anything starts.
type Mode string

const (
	// ModeTUN gives the host a network interface. The kernel owns the overlay
	// address, so ordinary programs bind it and ordinary tools see it. Needs
	// CAP_NET_ADMIN, and is the only mode that can forward subnets.
	ModeTUN Mode = "tun"

	// ModeProxy keeps the overlay entirely in userspace. Nothing on the host can
	// see it, and the only way in is a reverse proxy conflux publishes. Needs no
	// privileges at all, which is the whole reason it exists.
	ModeProxy Mode = "proxy"
)

// ConfigVersion is bumped when a field's meaning changes, never merely when one is
// added -- an added field is absent in an old file and takes its zero value, which
// is what encoding/json already does correctly.
const ConfigVersion = 1

// DefaultAPIBaseURL is where enrolment happens.
const DefaultAPIBaseURL = "https://api.veilnet.com.au"

// DefaultTUNName matches anchor's own default, so `ip link show anchor0` works
// whether a machine was brought up by conflux or by anchorctl directly.
const DefaultTUNName = "anchor0"

// Config is the operator's intent, and the only thing a reboot needs in order to
// reconstruct the running state without asking anybody anything.
type Config struct {
	Version int  `json:"version"`
	Mode    Mode `json:"mode"`

	// Taints are the compartment labels this anchor carries. Never empty after up
	// or proxy: an empty set is the realm's shared compartment, which every
	// unconfigured anchor is in, so conflux mints one rather than leave a machine
	// there by default.
	Taints []string `json:"taints"`

	// IPv4 is this machine's IPv4 -- an address, or an address and the length of the
	// range routed into the tunnel -- as the operator gave it. Either mode: with an
	// interface the host holds it, in userspace the anchor's own stack does.
	//
	// A pointer because the question is asked once in a machine's life and the
	// answer has to be remembered, including the answer "none". Nil is never asked;
	// an empty string is declined, and anchor then sends from its shared default and
	// cannot be reached by IPv4. See OverlayIPv4.
	IPv4 *string `json:"ipv4,omitempty"`

	// Subnets are interface names or prefixes this anchor forwards for its realm.
	// TUN only -- there is no host interface to forward out of in userspace.
	Subnets []string `json:"subnets,omitempty"`

	// Proxies are OVERLAYPORT[/NETWORK]=BACKEND specs. Userspace only -- with a
	// TUN the kernel owns the overlay address, so a service binds it directly.
	Proxies []string `json:"proxies,omitempty"`

	// Uplink carries layer 1 over a link instead of the host's IP network:
	// "fd:3" adopts a descriptor the supervisor was handed, "/dev/ttyUSB0" opens
	// a device, "/dev/ttyUSB0:115200" opens it and sets the line speed. With one
	// set no UDP socket is bound, no host interface is enumerated, and the anchor
	// advertises no address, because a cable has none.
	//
	// Orthogonal to Mode, which is the other question: the uplink is what the
	// anchor talks to the realm over, and the mode is what this machine gets out
	// of it. Either mode runs on either medium.
	Uplink string `json:"uplink,omitempty"`

	// Peers is where to start looking for the realm: "host:port", or
	// "anchorxxx@host:port" when the anchor expected to answer is known.
	//
	// Empty is the normal case and not a missing setting. The enrolment manifest
	// carries its issuer's own bootstrap list, and anchorctl uses it for exactly
	// the fields no flag named -- so passing nothing here is what lets the API
	// move its bootstrap nodes without every machine needing reconfiguring. This
	// is the override for pointing a machine at a realm the manifest does not
	// know about, which in practice means testing.
	Peers []string `json:"peers,omitempty"`

	// Port is the UDP port to bind on every interface, or zero to let the kernel
	// pick one. An anchor listens on every interface and only the port is
	// configurable, so this is a port and not an address: the host's addresses
	// change underneath it, and pinning one is a promise the host cannot keep.
	//
	// Zero is not passed to anchorctl at all, which is what leaves the manifest's
	// own listenPort in play -- the same rule Peers follows, for the same reason.
	// Meaningless beside an Uplink, where no socket is bound, and refused there.
	Port uint16 `json:"port,omitempty"`

	// LowLatency carries layer-2 frames on QUIC datagrams: no head-of-line
	// blocking between flows to one peer, and a lost frame stays lost rather than
	// holding up the ones behind it. A real trade rather than a better setting, so
	// it is off unless asked for.
	LowLatency bool `json:"lowLatency,omitempty"`

	// LANDiscovery probes the networks this host is attached to for anchors of the
	// same realm tree -- a third bootstrap source, tried with the configured and
	// remembered ones rather than as a fallback for when they are empty.
	//
	// A pointer because there are three answers and not two. Nil is "auto", which
	// passes no flag and so leaves the manifest's own lanDiscovery in play, the same
	// rule Port and Peers follow; anchor's default under that is on. True and false
	// are the operator saying so, and an explicit flag beats the manifest.
	//
	// Worth the operator's hand rather than the issuer's alone: a probe tells every
	// host on the link that an anchor is here and which tree it belongs to, and a
	// laptop repeats that on every network it attaches to. Nothing identifies the
	// anchor in it, but the disclosure is real and is not the issuer's to make
	// quietly -- the argument the two exit settings above make for themselves.
	//
	// Refused as an explicit yes beside an Uplink, where there is no host network to
	// probe. Nil and false are accepted there: anchor turns it off for an uplink
	// regardless, and refusing a default nobody chose would fail every uplink anchor
	// for a setting its operator never made.
	LANDiscovery *bool `json:"lanDiscovery,omitempty"`

	// ServeExit offers this anchor as a way out to the public internet, and
	// UseExit sends this machine's own internet traffic over the overlay. Both are
	// `conflux up`'s: an exit forwards out of a host interface, and anchor refuses
	// ServeExit without one. UseExit it accepts in userspace, where it covers only the
	// anchor's own traffic, so `conflux proxy` offers neither and clears both.
	//
	// Off by default and always passed explicitly, because an anchor that became
	// an internet exit on its own -- because a manifest said so -- is the worst
	// kind of surprise.
	ServeExit bool `json:"serveExit,omitempty"`
	UseExit   bool `json:"useExit,omitempty"`

	TUNName    string `json:"tunName,omitempty"`
	APIBaseURL string `json:"apiBaseUrl,omitempty"`

	// Export is where this machine's telemetry goes, and nil is the normal case:
	// an anchor exports nothing until its operator says where.
	//
	// It lives here rather than being set over the socket because an RPC-set
	// export dies with the daemon. `anchorctl export -endpoint ...` configures a
	// running process and nothing else, so the next restart -- a reboot, a crash,
	// a credential renewal that needed one -- comes back silent, and the only
	// symptom is a machine missing from a dashboard. A field in this file is
	// rendered to the daemon's own config on every start, which is the mechanism
	// anchor documents for exactly this.
	//
	// See export.go for why it mirrors anchor.v1.ExportConfig name for name.
	Export *Export `json:"export,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

// OverlayIPv4 is the configured IPv4, or "" when there is none.
func (c *Config) OverlayIPv4() string {
	if c.IPv4 == nil {
		return ""
	}

	return *c.IPv4
}

// TUNInterface is the interface name to ask for, defaulted.
func (c *Config) TUNInterface() string {
	if c.TUNName == "" {
		return DefaultTUNName
	}

	return c.TUNName
}

// APIBase is the enrolment endpoint, defaulted.
func (c *Config) APIBase() string {
	if c.APIBaseURL == "" {
		return DefaultAPIBaseURL
	}

	return c.APIBaseURL
}

// Validate applies anchor's rules here, where the error can name the flag the user
// typed, rather than letting them surface as an InvalidArgument from a child
// process three layers down. It accepts and refuses what anchor does, and adds one
// rule of conflux's own: a machine always carries a taint.
func (c *Config) Validate() error {
	switch c.Mode {
	case ModeTUN:
		if len(c.Proxies) > 0 {
			return fmt.Errorf(
				"mode is %q and %d proxy spec(s) are set: a reverse proxy needs userspace mode, "+
					"because with a host interface the kernel owns the overlay address and a service binds it directly",
				c.Mode, len(c.Proxies))
		}

	case ModeProxy:
		if len(c.Subnets) > 0 {
			return fmt.Errorf(
				"mode is %q and %d subnet(s) are set: forwarding a subnet needs a host interface to forward out of, "+
					"which userspace mode does not have",
				c.Mode, len(c.Subnets))
		}

		if c.ServeExit {
			return fmt.Errorf(
				"mode is %q and serveExit is set: an exit forwards the public internet out of a host interface, "+
					"which userspace mode does not have",
				c.Mode)
		}

	default:
		return fmt.Errorf("mode is %q, want %q or %q", c.Mode, ModeTUN, ModeProxy)
	}

	if len(c.Taints) == 0 {
		return fmt.Errorf("no taints: an anchor with none sits in the realm's shared compartment, which conflux never chooses silently")
	}

	if err := ValidateTaints(c.Taints); err != nil {
		return err
	}

	if err := c.Export.Validate(); err != nil {
		return err
	}

	if ip := c.OverlayIPv4(); ip != "" {
		if _, err := ParseOverlayIPv4(ip); err != nil {
			return err
		}
	}

	if _, err := ValidateProxies(c.Proxies); err != nil {
		return err
	}

	if c.Uplink != "" {
		if _, err := ParseUplinkSpec(c.Uplink); err != nil {
			return err
		}

		// anchor refuses the pair rather than ignoring the port, and it is right to:
		// a link binds no socket, so a port names nothing. Caught here so the message
		// can name both conflux flags instead of arriving from a child process.
		if c.Port != 0 {
			return fmt.Errorf(
				"a port and an uplink are set together: an uplink carries layer 1 over %s and binds no socket, "+
					"so there is no port to choose",
				c.Uplink)
		}

		// Only an explicit yes, which is anchor's own rule and its reason: a machine
		// configured once and later moved onto a cable would otherwise stop starting
		// for a default nobody chose. --lan-discovery no and the unset auto are both
		// accepted here, and anchor turns the probe off beside an uplink either way.
		if c.LANDiscovery != nil && *c.LANDiscovery {
			return fmt.Errorf(
				"--lan-discovery yes and an uplink are set together: an uplink carries layer 1 over %s, "+
					"so there is no host network to probe and nothing on a cable to answer",
				c.Uplink)
		}
	}

	if err := ValidatePeers(c.Peers); err != nil {
		return err
	}

	for _, s := range c.Subnets {
		if err := ValidateSubnet(s); err != nil {
			return err
		}
	}

	return nil
}

// Load reads the operator's intent. A missing file is fs.ErrNotExist and means
// "this machine has never been configured", which several callers treat as a state
// rather than a failure.
func Load(d paths.Dirs) (*Config, error) {
	b, err := os.ReadFile(d.ConfigFile())
	if err != nil {
		return nil, err
	}

	var c Config
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", d.ConfigFile(), err)
	}

	if c.Version > ConfigVersion {
		return nil, fmt.Errorf(
			"%s was written by a newer conflux (config version %d, this build understands %d)",
			d.ConfigFile(), c.Version, ConfigVersion)
	}

	return &c, nil
}

// Save writes it, atomically and 0600.
func Save(d paths.Dirs, c *Config) error {
	c.Version = ConfigVersion
	c.UpdatedAt = time.Now().UTC().Truncate(time.Second)

	if c.CreatedAt.IsZero() {
		c.CreatedAt = c.UpdatedAt
	}

	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}

	return WriteFileAtomic(d.ConfigFile(), append(b, '\n'), 0o600)
}
