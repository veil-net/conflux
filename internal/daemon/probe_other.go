//go:build !linux && !windows

package daemon

import (
	"runtime"

	"github.com/veil-net/conflux/internal/config"
	"golang.org/x/sys/unix"
)

// probeHost answers decide's questions about this host: on macOS and the BSDs only which
// ports are root's, who may open an uplink's device, and on macOS who may read a BPF device.
func probeHost(cfg *config.Config) hostFacts {
	h := hostFacts{reservedHigh: 1023, device: deviceFacts(cfg.Uplink), bpfOwn: -1}

	if cfg.Observer != nil {
		h.bpf, h.bpfOwn = bpfFacts()
	}

	if runtime.GOOS == "freebsd" {
		if n, err := unix.SysctlUint32("net.inet.ip.portrange.reservedhigh"); err == nil {
			h.reservedHigh = int(n)
		}
	}

	return h
}
