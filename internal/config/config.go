// Package config is what conflux keeps on disk.
//
// Three files, three lifetimes, deliberately not one:
//
//   - conflux.json  what the operator asked for. Written by up and proxy.
//   - state.json    what conflux derived. Written by the supervisor.
//   - manifest.b64  the identity. Written once, at enrolment, and never replaced
//     except to splice in a renewed chain.
//
// Splitting Config from State is not tidiness. The renewer rewrites NotAfter every
// few days from the supervisor, and a CLI rewrites Taints from a terminal; one file
// would make those a lost update. Splitting the manifest out again is because it is
// the only file with no second copy anywhere in the world.
package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"slices"
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

	// IPv4 is an operator-assigned overlay address carried as a prefix, e.g.
	// "10.128.0.7/24". Empty means IPv6-only, which is the common case: the v6
	// address is derived from the identity and needs no decision.
	IPv4 string `json:"ipv4,omitempty"`

	// Subnets are interface names or prefixes this anchor forwards for its realm.
	// TUN only -- there is no host interface to forward out of in userspace.
	Subnets []string `json:"subnets,omitempty"`

	// Proxies are OVERLAYPORT[/NETWORK]=BACKEND specs. Userspace only -- with a
	// TUN the kernel owns the overlay address, so a service binds it directly.
	Proxies []string `json:"proxies,omitempty"`

	TUNName    string `json:"tunName,omitempty"`
	APIBaseURL string `json:"apiBaseUrl,omitempty"`

	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
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
// process three layers down.
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

		if c.IPv4 != "" {
			return fmt.Errorf("mode is %q and an overlay IPv4 is set: there is no host interface to assign it to", c.Mode)
		}

	default:
		return fmt.Errorf("mode is %q, want %q or %q", c.Mode, ModeTUN, ModeProxy)
	}

	if len(c.Taints) == 0 {
		return fmt.Errorf("no taints: an anchor with none sits in the realm's shared compartment, which conflux never chooses silently")
	}

	for _, t := range c.Taints {
		if err := ValidateTaint(t); err != nil {
			return err
		}
	}

	if c.IPv4 != "" {
		if _, err := ParseOverlayIPv4(c.IPv4); err != nil {
			return err
		}
	}

	for _, s := range c.Proxies {
		if _, err := ParseProxySpec(s); err != nil {
			return err
		}
	}

	if err := c.validateSubnets(); err != nil {
		return err
	}

	return nil
}

func (c *Config) validateSubnets() error {
	seen := make(map[string]bool, len(c.Subnets))

	for _, s := range c.Subnets {
		if s == "" {
			return fmt.Errorf("empty subnet entry")
		}

		if seen[s] {
			return fmt.Errorf("subnet %q is listed twice", s)
		}

		seen[s] = true

		// An entry is either an interface name, which anchor expands to every
		// private network on it, or a prefix. Only the prefix form is checkable
		// without touching the host, and it is the form people get wrong.
		if p, err := netip.ParsePrefix(s); err == nil && !p.Addr().IsPrivate() && !p.Addr().IsLinkLocalUnicast() {
			return fmt.Errorf(
				"subnet %s is not a private network: anchor forwards private networks only, and reaching the public internet through an anchor is what an exit is for",
				s)
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

	c.Taints = slices.Clone(c.Taints)

	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}

	return WriteFileAtomic(d.ConfigFile(), append(b, '\n'), 0o600)
}

// Delete removes it. A file that is already gone is success.
func Delete(d paths.Dirs) error {
	if err := os.Remove(d.ConfigFile()); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}
