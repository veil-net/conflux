package daemon

import (
	"io/fs"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/config"
)

// roomy is a Linux host that asks nothing of anchord's account: buffers past quic-go's
// floor, no firewall that answers only root, an ambient set, a tun anybody may open.
func roomy() hostFacts {
	return hostFacts{
		nft:              true,
		iptables:         true,
		ambient:          true,
		tun:              &fileFacts{path: "/dev/net/tun", gid: 0, mode: 0o666},
		rmemMax:          bufferFloor,
		wmemMax:          bufferFloor,
		unprivilegedPort: 1024,
		reservedHigh:     1023,
	}
}

func proxyCfg() *config.Config { return &config.Config{Mode: config.ModeProxy} }
func tunCfg() *config.Config   { return &config.Config{Mode: config.ModeTUN} }

// observing is cfg with the observer on, and observeCfg the observer alone, with the
// anchor's settings it keeps for later: a low port and an uplink only root may open.
func observing(cfg *config.Config) *config.Config { cfg.Observer = &config.Observer{}; return cfg }
func observeCfg() *config.Config {
	return &config.Config{Mode: config.ModeObserve, Observer: &config.Observer{}, Port: 443, Uplink: "/dev/ttyUSB0"}
}

// TestDecideTable: anchord gives up root and every capability wherever that costs it
// nothing, and keeps exactly what each host and mode need -- saying why.
func TestDecideTable(t *testing.T) {
	legacy, firewalld, oldKernel, rootTun, noNft, tight := roomy(), roomy(), roomy(), roomy(), roomy(), roomy()
	legacy.legacy = "iptables"
	firewalld.firewalld = true
	oldKernel.ambient = false
	rootTun.tun.mode = 0o600
	noNft.nft = false
	tight.rmemMax = 212992

	groupTun := roomy()
	groupTun.tun = &fileFacts{path: "/dev/net/tun", gid: 108, mode: 0o660}

	for _, c := range []struct {
		name    string
		goos    string
		cfg     *config.Config
		port    int
		h       hostFacts
		account bool
		caps    []string
		groups  []int
		why     string
		bpf     string
	}{
		{name: "linux proxy", goos: "linux", cfg: proxyCfg(), h: roomy(), account: true},
		{name: "linux proxy, small buffers", goos: "linux", cfg: proxyCfg(), h: tight, account: true,
			caps: []string{capNetAdmin}, why: "UDP buffers"},
		{name: "linux proxy over a link binds no socket", goos: "linux",
			cfg: &config.Config{Mode: config.ModeProxy, Uplink: "/dev/ttyUSB0:115200"}, h: tight, account: true},
		{name: "linux proxy, port 443", goos: "linux", cfg: proxyCfg(), port: 443, h: roomy(), account: true,
			caps: []string{capNetBindService}, why: "port 443"},
		{name: "linux proxy, port 443 unprivileged by sysctl", goos: "linux", cfg: proxyCfg(), port: 443,
			h: func() hostFacts { h := roomy(); h.unprivilegedPort = 80; return h }(), account: true},
		{name: "linux tun", goos: "linux", cfg: tunCfg(), h: roomy(), account: true, caps: []string{capNetAdmin}},
		{name: "linux tun, tun device's group", goos: "linux", cfg: tunCfg(), h: groupTun, account: true,
			caps: []string{capNetAdmin}, groups: []int{108}},
		{name: "linux tun, iptables and no nft", goos: "linux", cfg: tunCfg(), h: noNft, account: true,
			caps: []string{capNetAdmin, capNetRaw}},
		{name: "linux tun, buffers are CAP_NET_ADMIN's already", goos: "linux", cfg: tunCfg(), h: func() hostFacts {
			h := roomy()
			h.rmemMax = 0

			return h
		}(), account: true, caps: []string{capNetAdmin}},
		{name: "linux tun, firewalld", goos: "linux", cfg: tunCfg(), h: firewalld, why: "firewalld"},
		{name: "linux tun, legacy iptables", goos: "linux", cfg: tunCfg(), h: legacy, why: "legacy backend"},
		{name: "linux tun, no ambient set", goos: "linux", cfg: tunCfg(), h: oldKernel, why: "cannot give a capability"},
		{name: "linux tun, root's tun device", goos: "linux", cfg: tunCfg(), h: rootTun, why: "opens only for root"},
		{name: "macos proxy", goos: "darwin", cfg: proxyCfg(), port: 443, h: roomy(), account: true},
		{name: "macos tun", goos: "darwin", cfg: tunCfg(), h: roomy(), why: "utun"},
		{name: "freebsd proxy", goos: "freebsd", cfg: proxyCfg(), h: roomy(), account: true},
		{name: "freebsd proxy, reserved port", goos: "freebsd", cfg: proxyCfg(), port: 80, h: roomy(), why: "reserved"},
		{name: "openbsd proxy, low port", goos: "openbsd", cfg: proxyCfg(), port: 80, h: roomy(), why: "reserved"},
		{name: "openbsd tun", goos: "openbsd", cfg: tunCfg(), h: roomy(), why: "only root can open a tun"},
		{name: "windows proxy", goos: "windows", cfg: proxyCfg(), port: 443, h: hostFacts{}, account: true},
		{name: "windows tun", goos: "windows", cfg: tunCfg(), h: hostFacts{}, why: "wintun"},

		// The observer: a copy of what the host carries, which is CAP_NET_RAW on Linux, read
		// access to the BPF devices on macOS, and nothing beyond LOCAL SERVICE on Windows.
		// Observing alone, the anchor's kept settings -- a low port, a root-only uplink, the
		// buffers -- grant nothing.
		{name: "linux observing", goos: "linux", cfg: observeCfg(), h: rootUplink(tight), account: true,
			caps: []string{capNetRaw}, why: "for the observer"},
		{name: "linux proxy and observer", goos: "linux", cfg: observing(proxyCfg()), h: roomy(), account: true,
			caps: []string{capNetRaw}},
		{name: "linux proxy and observer, small buffers", goos: "linux", cfg: observing(proxyCfg()), h: tight, account: true,
			caps: []string{capNetAdmin, capNetRaw}},
		{name: "linux tun and observer", goos: "linux", cfg: observing(tunCfg()), h: roomy(), account: true,
			caps: []string{capNetAdmin, capNetRaw}},
		{name: "linux observing, no ambient set", goos: "linux", cfg: observeCfg(), h: oldKernel, why: "CAP_NET_RAW"},
		{name: "macos observing", goos: "darwin", cfg: observeCfg(), h: rootUplink(roomy()), account: true,
			why: "/dev/bpf*", bpf: BPFOwn},
		{name: "macos observing, ChmodBPF's group", goos: "darwin", cfg: observeCfg(),
			h: bpfReadBy(roomy(), 101, 0o640), account: true, groups: []int{101}, bpf: BPFGroup},
		{name: "macos observing, the devices already the account's", goos: "darwin", cfg: observeCfg(),
			h:       func() hostFacts { h := bpfReadBy(roomy(), 299, 0o640); h.bpfOwn = 299; return h }(),
			account: true, bpf: BPFOwn},
		{name: "macos proxy and observer", goos: "darwin", cfg: observing(proxyCfg()), h: roomy(), account: true,
			bpf: BPFOwn},
		{name: "macos tun and observer", goos: "darwin", cfg: observing(tunCfg()), h: roomy(), why: "utun"},
		{name: "windows observing", goos: "windows", cfg: observeCfg(), h: hostFacts{}, account: true},
		{name: "windows proxy and observer", goos: "windows", cfg: observing(proxyCfg()), h: hostFacts{}, account: true},
		{name: "windows tun and observer", goos: "windows", cfg: observing(tunCfg()), h: hostFacts{}, why: "wintun"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := decide(c.goos, c.cfg, c.port, c.h)

			if p.Account != c.account || !slices.Equal(p.Caps, c.caps) || !slices.Equal(p.Groups, c.groups) {
				t.Errorf("decide = account %v, caps %v, groups %v (%q); want account %v, caps %v, groups %v",
					p.Account, p.Caps, p.Groups, p.Why, c.account, c.caps, c.groups)
			}

			if c.why != "" && !strings.Contains(p.Why, c.why) {
				t.Errorf("the reason is %q, which does not say %q", p.Why, c.why)
			}

			if p.BPF != c.bpf {
				t.Errorf("BPF = %q, want %q", p.BPF, c.bpf)
			}

			// no_new_privs where anchord runs no command at all: userspace mode on Linux, and
			// observing alone.
			if want := c.account && c.goos == "linux" && c.cfg.Mode != config.ModeTUN; p.NoNewPrivs != want {
				t.Errorf("NoNewPrivs = %v, want %v", p.NoNewPrivs, want)
			}
		})
	}
}

// TestDecideUplinkDevice: a device its group may open is opened through that group; one
// only root may open keeps anchord root, and one not there yet decides nothing until it is.
func TestDecideUplinkDevice(t *testing.T) {
	cfg := &config.Config{Mode: config.ModeProxy, Uplink: "/dev/ttyUSB0:115200"}

	h := roomy()
	h.device = &fileFacts{path: "/dev/ttyUSB0", gid: 20, mode: 0o660}

	if p := decide("linux", cfg, 0, h); !p.Account || !slices.Equal(p.Groups, []int{20}) {
		t.Errorf("a dialout device: account %v, groups %v; want the account, in group 20", p.Account, p.Groups)
	}

	h.device.mode = 0o600
	if p := decide("linux", cfg, 0, h); p.Account || !strings.Contains(p.Why, "/dev/ttyUSB0") {
		t.Errorf("a device only root opens: account %v (%q); want root, naming it", p.Account, p.Why)
	}

	h.device = nil
	if p := decide("linux", cfg, 0, h); !p.Account || len(p.Groups) != 0 {
		t.Errorf("a device not there yet: account %v, groups %v", p.Account, p.Groups)
	}
}

// TestKeepCapsSaysWhyForWhatIsKept: a capability the supervisor cannot give is dropped,
// and the reason for it goes with it.
func TestKeepCapsSaysWhyForWhatIsKept(t *testing.T) {
	h := roomy()
	h.nft = false

	p := decide("linux", tunCfg(), 0, h)
	p.keepCaps(func(c string) bool { return c != capNetRaw })

	if !slices.Equal(p.Caps, []string{capNetAdmin}) || strings.Contains(p.Why, capNetRaw) {
		t.Errorf("after keepCaps: %v, %q", p.Caps, p.Why)
	}
}

func TestListenPort(t *testing.T) {
	if got := listenPort(&config.Config{Port: 4711}, 443); got != 4711 {
		t.Errorf("conflux.json's port: %d", got)
	}

	if got := listenPort(&config.Config{}, 443); got != 443 {
		t.Errorf("the manifest's port: %d", got)
	}

	if got := listenPort(&config.Config{Uplink: "/dev/ttyS0", Port: 443}, 443); got != 0 {
		t.Errorf("a link binds no port: %d", got)
	}

	if got := listenPort(observeCfg(), 443); got != 0 {
		t.Errorf("observing alone binds no port: %d", got)
	}
}

// rootUplink is h with an uplink's device only root may open, which an anchor over it would
// need root for.
func rootUplink(h hostFacts) hostFacts {
	h.device = &fileFacts{path: "/dev/ttyUSB0", gid: 0, mode: 0o600}

	return h
}

// bpfReadBy is h with BPF devices a group of the host's may read.
func bpfReadBy(h hostFacts, gid int, mode fs.FileMode) hostFacts {
	h.bpf, h.bpfOwn = &fileFacts{path: "/dev/bpf0", gid: gid, mode: mode}, -1

	return h
}

func TestPrivilegeString(t *testing.T) {
	for _, c := range []struct {
		p    Privilege
		want string
	}{
		{Privilege{Account: true, As: "conflux"}, "conflux, with no privilege"},
		{Privilege{Account: true, As: "conflux", Caps: []string{capNetAdmin}, Why: "CAP_NET_ADMIN for its interface"},
			"conflux, with CAP_NET_ADMIN for its interface"},
		{Privilege{As: "root", Why: "only root can open a utun on macOS"}, "root — only root can open a utun on macOS"},
		{Privilege{Account: true, As: "_conflux", BPF: BPFOwn, Why: "read access to /dev/bpf*, for the observer"},
			"_conflux, with read access to /dev/bpf*, for the observer"},
	} {
		if got := c.p.String(); got != c.want {
			t.Errorf("%+v = %q, want %q", c.p, got, c.want)
		}
	}
}

// TestServiceSID: the SID Windows derives for a service, against one everybody knows.
func TestServiceSID(t *testing.T) {
	if got, want := serviceSID("TrustedInstaller"), "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"; got != want {
		t.Errorf("serviceSID(TrustedInstaller) = %s, want %s", got, want)
	}

	if serviceSID("conflux") != serviceSID("CONFLUX") {
		t.Error("a service's SID does not depend on how its name is cased")
	}
}

// TestAnchordEnv: the token in the environment, and nothing of the service manager's or of
// conflux's own, and for the account nobody's home.
func TestAnchordEnv(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "/run/systemd/notify")
	t.Setenv("CONFLUX_DIR", "/srv/x")
	t.Setenv("HOME", "/root")
	t.Setenv("ANCHORD_TOKEN", "stale")

	env := anchordEnv(Privilege{Account: true, As: "conflux"}, "fresh")

	gone := []string{"NOTIFY_SOCKET=", "CONFLUX_DIR=", "ANCHORD_TOKEN=stale"}
	if runtime.GOOS != "windows" {
		gone = append(gone, "HOME=/root")
	}

	for _, kv := range env {
		for _, gone := range gone {
			if strings.HasPrefix(kv, gone) {
				t.Errorf("anchord's environment has %q", kv)
			}
		}
	}

	if !slices.Contains(env, "ANCHORD_TOKEN=fresh") {
		t.Error("anchord's environment has no token")
	}
}
