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
// anchord handles SIGTERM by shutting down cleanly and saying goodbye first.
//
// The bool is for Windows, where a service cannot deliver anything at all and the caller
// must not spend killTimeout waiting for an answer to a question nobody was asked. Here it
// is very nearly always true, and false is worth reporting for the same reason: a signal
// that did not arrive is not one worth waiting on.
func terminate(cmd *exec.Cmd) bool {
	if cmd.Process == nil {
		return false
	}

	if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
		if err := syscall.Kill(-pgid, syscall.SIGTERM); err == nil {
			return true
		}
	}

	return cmd.Process.Signal(syscall.SIGTERM) == nil
}
