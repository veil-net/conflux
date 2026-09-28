//go:build !windows

package daemon

import (
	"os/exec"
	"syscall"
)

// procAttr puts anchord in its own process group, so that a hung daemon and
// anything it spawned can be signalled together rather than one at a time.
func procAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

// terminate asks the whole group to stop, and reports whether the signal was delivered.
// anchord handles SIGTERM by closing its anchor, so it says goodbye, and exiting.
//
// The group is numbered for anchord's own pid, which Setpgid made its leader. The bool
// is for Windows, where a service cannot deliver anything at all; here it is very nearly
// always true, and false sends shutdown the way Windows goes, since a signal that did not
// arrive is not one worth waiting on.
func terminate(cmd *exec.Cmd) bool {
	if syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM) == nil {
		return true
	}

	return cmd.Process.Signal(syscall.SIGTERM) == nil
}
