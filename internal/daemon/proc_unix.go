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

// terminate asks the whole group to stop. anchord handles SIGTERM by shutting down
// cleanly and saying goodbye first.
func terminate(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}

	if pgid, err := syscall.Getpgid(cmd.Process.Pid); err == nil {
		if err := syscall.Kill(-pgid, syscall.SIGTERM); err == nil {
			return
		}
	}

	_ = cmd.Process.Signal(syscall.SIGTERM)
}
