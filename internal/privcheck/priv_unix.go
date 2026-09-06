//go:build !windows

package privcheck

import (
	"fmt"
	"os"
	"strings"
)

// Elevated reports whether this process can do what conflux needs: write /etc and
// /var/lib, talk to the service manager, and open a TUN device.
func Elevated() bool { return os.Geteuid() == 0 }

// Describe names the current identity, for a status line.
func Describe() string {
	if Elevated() {
		return "root"
	}

	return fmt.Sprintf("uid %d", os.Geteuid())
}

// Require refuses, with the command that would work.
//
// Every state-changing conflux verb needs root, including proxy -- userspace mode
// itself needs no privileges at all, but registering a boot service and writing to
// /etc does, and a proxy that vanishes on reboot is not what anyone asked for.
func Require(what, retry string) error {
	if Elevated() {
		return nil
	}

	return fmt.Errorf("%s needs root.\n  try:  sudo %s", what, strings.TrimSpace(retry))
}
