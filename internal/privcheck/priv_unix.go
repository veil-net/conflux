//go:build !windows

package privcheck

import (
	"fmt"
	"os"
	"runtime"
	"strings"
)

// Elevated reports whether this process can do what conflux needs: write /etc and
// /var/lib, talk to the service manager, and open a TUN device. A variable so a test
// can be the account that is refused.
var Elevated = func() bool { return os.Geteuid() == 0 }

// Require refuses, with the command that would work.
//
// Every state-changing conflux verb needs root, including proxy -- userspace mode
// itself needs no privileges at all, but registering a boot service and writing to
// /etc does, and a proxy that vanishes on reboot is not what anyone asked for.
func Require(what, retry string) error {
	if Elevated() {
		return nil
	}

	return fmt.Errorf("%s needs root.\n  try:  %s", what, Retry(retry))
}

// Retry is a command as root would run it: through doas on OpenBSD, whose base system
// has it and not sudo, and sudo everywhere else.
func Retry(cmd string) string {
	if runtime.GOOS == "openbsd" {
		return "doas " + strings.TrimSpace(cmd)
	}

	return "sudo " + strings.TrimSpace(cmd)
}
