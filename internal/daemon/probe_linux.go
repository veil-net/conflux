package daemon

import (
	"context"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"github.com/veil-net/conflux/internal/config"
	"golang.org/x/sys/unix"
)

// probeHost answers decide's questions about this host. The firewall's are asked only for
// a TUN, which is the only mode that changes one; each is a command anchor itself runs,
// asked the way anchor asks it.
func probeHost(cfg *config.Config) hostFacts {
	h := hostFacts{
		ambient:          ambientSupported(),
		rmemMax:          sysctlInt("/proc/sys/net/core/rmem_max"),
		wmemMax:          sysctlInt("/proc/sys/net/core/wmem_max"),
		unprivilegedPort: 1024,
		device:           deviceFacts(cfg.Uplink),
	}

	if n := sysctlInt("/proc/sys/net/ipv4/ip_unprivileged_port_start"); n > 0 {
		h.unprivilegedPort = n
	}

	if cfg.Mode != config.ModeTUN {
		return h
	}

	h.tun = fileAt("/dev/net/tun")
	h.firewalld = firewalldRuns()
	_, err := exec.LookPath("nft")
	h.nft = err == nil

	for _, tool := range []string{"iptables", "ip6tables"} {
		switch backend := iptablesBackend(tool); backend {
		case "":
		case "nf_tables":
			h.iptables = true
		default:
			if h.legacy == "" {
				h.legacy = tool
			}
		}
	}

	return h
}

// firewalldRuns is anchor's own test (hostsetup.firewalldRuns): firewall-cmd installed,
// and saying it is running.
func firewalldRuns() bool {
	if _, err := exec.LookPath("firewall-cmd"); err != nil {
		return false
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	return exec.CommandContext(ctx, "firewall-cmd", "--state").Run() == nil
}

// iptablesBackend is "nf_tables" or "legacy" for an installed tool, and "" for one that
// is not. A version too old to name its backend is legacy, which is all there was.
func iptablesBackend(tool string) string {
	if _, err := exec.LookPath(tool); err != nil {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, tool, "--version").Output()
	if err != nil {
		return ""
	}

	if strings.Contains(string(out), "nf_tables") {
		return "nf_tables"
	}

	return "legacy"
}

// ambientSupported is whether this kernel has an ambient capability set: one without
// refuses the question itself.
func ambientSupported() bool {
	_, err := unix.PrctlRetInt(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_IS_SET, unix.CAP_NET_ADMIN, 0, 0)

	return err == nil
}

func sysctlInt(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}

	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))

	return n
}
