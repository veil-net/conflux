//go:build !windows

package daemon

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
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

// kill ends the group outright, as terminate asked it to end: anything anchord started
// would otherwise keep its output pipe open and the wait for anchord with it.
func kill(cmd *exec.Cmd) {
	if syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) != nil {
		_ = cmd.Process.Kill()
	}
}

// bind is Windows's; a Unix supervisor's anchord is reached through its pid and group, and
// what it leaves behind through its account (see killLeftovers).
func bind(*os.Process) (func(), error) { return func() {}, nil }

// alive reports whether a process with this pid exists. EPERM is one that does and is
// not ours to signal.
func alive(pid int) bool {
	err := unix.Kill(pid, 0)

	return err == nil || errors.Is(err, unix.EPERM)
}

// stopOrphan stops an anchord this process did not start and so cannot wait for: SIGTERM,
// which closes its anchor, then SIGKILL once killTimeout has passed, each to its group
// where it leads one, as every anchord a supervisor started does.
func stopOrphan(pid int) error {
	target := pid
	if pgid, err := unix.Getpgid(pid); err == nil && pgid == pid {
		target = -pid
	}

	for _, step := range []struct {
		sig    unix.Signal
		within time.Duration
	}{{unix.SIGTERM, killTimeout}, {unix.SIGKILL, 5 * time.Second}} {
		if err := unix.Kill(target, step.sig); err != nil && !errors.Is(err, unix.ESRCH) {
			return err
		}

		for deadline := time.Now().Add(step.within); alive(pid); time.Sleep(50 * time.Millisecond) {
			if time.Now().After(deadline) {
				break
			}
		}

		if !alive(pid) {
			return nil
		}
	}

	return fmt.Errorf("pid %d is still running", pid)
}
