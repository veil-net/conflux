package daemon

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
)

// Who anchord runs as.
//
// The rule: anchord gives up root, or a capability, wherever doing so costs no operation
// and no function, and keeps whatever this host and this configuration need. So it runs
// as the installation's own unprivileged account -- with exactly the Linux capabilities
// its mode needs, and on Linux in userspace mode with no_new_privs as well -- unless the
// platform, the host or the supervisor needs it to be root, and then `conflux status`
// says why.
//
// decide is the whole table, and pure: the host's answers arrive as hostFacts, so every
// combination is a test. What the supervisor itself can give -- the account, the
// capabilities it holds, a binary that runs as that account at all -- is settled after,
// in grant, and only ever takes privilege back to what the supervisor has.

// Privilege is what one anchord was started with, recorded in <run>/anchord.priv for
// `conflux status` and for the supervisor that starts the next one.
type Privilege struct {
	// Account is true for the installation's unprivileged account, and false for the
	// supervisor's own identity: root, SYSTEM, or whoever ran a supervisor that is
	// neither.
	Account bool `json:"account"`

	// As names who that is, for a person.
	As string `json:"as,omitempty"`

	UID int `json:"uid,omitempty"`
	GID int `json:"gid,omitempty"`

	// Groups are supplementary groups beyond the account's own: a device's, so anchord
	// can open it.
	Groups []int `json:"groups,omitempty"`

	// Caps are the Linux capabilities the account is given, by name.
	Caps []string `json:"caps,omitempty"`

	// NoNewPrivs is set where anchord runs nothing, so nothing it runs can gain what it
	// was not given.
	NoNewPrivs bool `json:"noNewPrivs,omitempty"`

	// Why says why anchord keeps what it keeps: root, or each capability.
	Why string `json:"why,omitempty"`

	// Dir is the anchor directory it was given, which is the account's or root's.
	Dir string `json:"dir,omitempty"`

	// reasons says what each capability is for, which Why is made from.
	reasons map[string]string
}

// The capabilities anchord is ever given, by name and by number.
const (
	capNetBindService = "CAP_NET_BIND_SERVICE"
	capNetAdmin       = "CAP_NET_ADMIN"
	capNetRaw         = "CAP_NET_RAW"
)

// bufferFloor is the net.core.rmem_max and wmem_max under which quic-go cannot size its
// UDP buffers without CAP_NET_ADMIN.
//
// quic-go asks for 7 MiB (sys_conn_buffers_nonopenbsd.go, desiredBufferSize), and the
// kernel doubles what it is asked for up to twice the limit, so half that is enough. Below
// it quic-go falls back to SO_RCVBUFFORCE and SO_SNDBUFFORCE, which need CAP_NET_ADMIN,
// and without them it runs on the system's default buffers -- slower on any fast path.
const bufferFloor = 7 << 20 / 2

// hostFacts is what decide needs to know about the host, gathered by probeHost.
type hostFacts struct {
	// firewalld is running: it takes changes only from root, over D-Bus.
	firewalld bool

	// legacy names an installed iptables or ip6tables on the legacy backend, which needs
	// root for its lock in /run and raw sockets. "" when none is.
	legacy string

	// nft is installed. Without it anchor's router falls back to iptables with ipset,
	// whose set match opens a raw socket.
	nft bool

	// iptables is installed, on nf_tables.
	iptables bool

	// ambient is whether the kernel has an ambient capability set at all (4.3 and later):
	// without one no capability reaches a process that is not root.
	ambient bool

	// tun is /dev/net/tun, or nil where there is none.
	tun *fileFacts

	// rmemMax and wmemMax are net.core's, or 0 when unread.
	rmemMax, wmemMax int

	// unprivilegedPort is net.ipv4.ip_unprivileged_port_start on Linux: 1024 unless set.
	unprivilegedPort int

	// reservedHigh is net.inet.ip.portrange.reservedhigh on FreeBSD: 1023 unless set.
	reservedHigh int

	// device is the uplink's device, or nil where there is none or it is not there yet.
	device *fileFacts
}

// fileFacts is who may open a device.
type fileFacts struct {
	path string
	gid  int
	mode fs.FileMode
}

// decide is who anchord runs as with this configuration on this host: as the account,
// with what and why, or as the supervisor and why. port is the UDP port anchor binds,
// 0 for one the kernel picks or none.
func decide(goos string, cfg *config.Config, port int, h hostFacts) Privilege {
	tun := cfg.Mode == config.ModeTUN

	p := Privilege{Account: true, reasons: map[string]string{}}

	grant := func(cap, reason string) {
		if !slices.Contains(p.Caps, cap) {
			p.Caps = append(p.Caps, cap)
		}

		if r := p.reasons[cap]; r != "" {
			reason = r + ", and " + reason
		}

		p.reasons[cap] = reason
	}

	if tun {
		switch goos {
		case "darwin":
			return asSupervisor("only root can open a utun on macOS")
		case "freebsd", "openbsd":
			return asSupervisor("only root can open a tun on " + goos)
		case "windows":
			return asSupervisor("wintun takes an adapter only from SYSTEM")
		case "linux":
			switch {
			case h.firewalld:
				return asSupervisor("firewalld takes changes only from root, and anchord lets its port in through it")
			case h.legacy != "":
				return asSupervisor(h.legacy + " is on the legacy backend, which only root can change")
			case !h.ambient:
				return asSupervisor("this kernel cannot give a capability to a process that is not root")
			}

			if h.tun != nil {
				gid, ok := opens(h.tun)
				if !ok {
					return asSupervisor(h.tun.path + " opens only for root")
				}

				p.Groups = appendGroup(p.Groups, gid)
			}

			grant(capNetAdmin, "for its interface")

			if !h.nft && h.iptables {
				grant(capNetRaw, "for iptables' set match, with no nft installed")
			}
		}
	}

	if port > 0 && port < 1024 {
		switch goos {
		case "linux":
			if port < h.unprivilegedPort {
				if !h.ambient {
					return asSupervisor(fmt.Sprintf("port %d is root's, and this kernel cannot give a capability to a "+
						"process that is not root", port))
				}

				grant(capNetBindService, "for port "+strconv.Itoa(port))
			}
		case "freebsd":
			if port <= h.reservedHigh {
				return asSupervisor(fmt.Sprintf("port %d is reserved for root (net.inet.ip.portrange.reservedhigh is %d)",
					port, h.reservedHigh))
			}
		case "openbsd":
			return asSupervisor(fmt.Sprintf("port %d is reserved for root on OpenBSD", port))
		}
	}

	if cfg.Uplink != "" && h.device != nil {
		gid, ok := opens(h.device)
		if !ok {
			return asSupervisor(h.device.path + " opens only for root")
		}

		p.Groups = appendGroup(p.Groups, gid)
	}

	// The kernel's buffers are sized by the anchor's one socket, which an uplink does not
	// bind. With a TUN, CAP_NET_ADMIN is there already.
	if goos == "linux" && !tun && cfg.Uplink == "" && (h.rmemMax < bufferFloor || h.wmemMax < bufferFloor) {
		if !h.ambient {
			return asSupervisor("quic-go needs CAP_NET_ADMIN for its UDP buffers, and this kernel cannot give a " +
				"capability to a process that is not root")
		}

		grant(capNetAdmin, fmt.Sprintf("to size its UDP buffers: net.core.rmem_max and wmem_max at %d or more "+
			"remove the need", bufferFloor))
	}

	// Userspace mode runs no command at all, so nothing is lost by refusing it any gain;
	// a TUN's runs nft and iptables, whose SELinux transitions no_new_privs would block.
	p.NoNewPrivs = goos == "linux" && !tun
	p.explain()

	return p
}

// keepCaps leaves only the capabilities keep says may stay, and says why for those.
func (p *Privilege) keepCaps(keep func(string) bool) {
	p.Caps = slices.DeleteFunc(p.Caps, func(c string) bool { return !keep(c) })
	p.explain()
}

// explain makes Why from what each capability is for.
func (p *Privilege) explain() {
	why := make([]string, 0, len(p.Caps))

	for _, c := range p.Caps {
		why = append(why, c+" "+p.reasons[c])
	}

	p.Why = strings.Join(why, "; ")
}

// asSupervisor is p given up: anchord runs as the supervisor does, and why.
func asSupervisor(why string) Privilege { return Privilege{Why: why} }

// opens reports whether the account can open a device read-write, and the group to add
// it to when only that group can: every account may, or the device's group may and it is
// not root's.
func opens(f *fileFacts) (gid int, ok bool) {
	switch perm := f.mode.Perm(); {
	case perm&0o006 == 0o006:
		return -1, true
	case perm&0o060 == 0o060 && f.gid != 0:
		return f.gid, true
	}

	return 0, false
}

func appendGroup(groups []int, gid int) []int {
	if gid < 0 || slices.Contains(groups, gid) {
		return groups
	}

	return append(groups, gid)
}

// listenPort is the port anchor binds: conflux.json's, the manifest's where that names
// none, and none over an uplink.
func listenPort(cfg *config.Config, manifestPort int) int {
	switch {
	case cfg.Uplink != "":
		return 0
	case cfg.Port != 0:
		return int(cfg.Port)
	}

	return manifestPort
}

// String is the privilege as `conflux status` prints it.
func (p Privilege) String() string {
	who := p.As
	if who == "" {
		who = "the supervisor's account"
	}

	switch {
	case p.Account && len(p.Caps) == 0:
		return who + ", with no privilege"
	case p.Account:
		return who + ", with " + p.Why
	case p.Why != "":
		return who + " — " + p.Why
	}

	return who
}

// recordPrivilege writes down what the anchord just started was given.
func recordPrivilege(d paths.Dirs, p Privilege) error {
	b, err := json.Marshal(p)
	if err != nil {
		return err
	}

	return config.WriteFileAtomic(d.PrivilegeFile(), append(b, '\n'), 0o600)
}

// RecordedPrivilege is what the last anchord this root started was given, or false when
// no record says.
func RecordedPrivilege(d paths.Dirs) (Privilege, bool) {
	var p Privilege

	b, err := os.ReadFile(d.PrivilegeFile())
	if err != nil || json.Unmarshal(b, &p) != nil {
		return Privilege{}, false
	}

	return p, true
}

// ActiveAnchorDir is the anchor directory the last anchord started was given, and where
// one is not recorded, whichever of the two exists, the account's first.
func ActiveAnchorDir(d paths.Dirs) string {
	if p, ok := RecordedPrivilege(d); ok && (p.Dir == d.AnchorDir() || p.Dir == d.RootAnchorDir()) {
		return p.Dir
	}

	if _, err := os.Lstat(d.AnchorDir()); err == nil {
		return d.AnchorDir()
	}

	return d.RootAnchorDir()
}

// sameGrant reports whether two decisions start the same anchord: the same identity, the
// same capabilities and groups, the same directory.
func sameGrant(a, b Privilege) bool {
	return a.Account == b.Account && a.UID == b.UID && a.GID == b.GID && a.NoNewPrivs == b.NoNewPrivs &&
		slices.Equal(a.Caps, b.Caps) && slices.Equal(a.Groups, b.Groups) && a.Dir == b.Dir
}
