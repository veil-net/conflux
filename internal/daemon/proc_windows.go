//go:build windows

package daemon

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// procAttr gives anchord its own process group, which is what makes a console
// control event deliverable to it alone.
func procAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: windows.CREATE_NEW_PROCESS_GROUP}
}

// terminate asks anchord to stop.
//
// Go maps CTRL_BREAK to os.Interrupt, which anchord already handles. Inside a
// Windows service this fails, because a service has no console to send an event to
// -- so the failure is expected rather than exceptional, and the caller falls
// through to Kill after its timeout. That is safe only because the anchor was
// already closed with `anchorctl stop` before any of this.
func terminate(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}

	_ = windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(cmd.Process.Pid))
}
