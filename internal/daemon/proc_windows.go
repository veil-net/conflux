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

// terminate asks anchord to stop, and reports whether anything was actually asked.
//
// Go maps CTRL_BREAK to os.Interrupt, which anchord already handles, and
// CREATE_NEW_PROCESS_GROUP above is what makes the event deliverable to it alone. That
// works from a console and cannot work from a service: GenerateConsoleCtrlEvent needs a
// console shared with the target, and a service has none. So on Windows the answer here
// is false every time conflux runs the way conflux actually runs on Windows.
//
// **The bool is the fix.** It was a bare call, so shutdown could not tell "asked and
// waiting" from "never asked", and waited out killTimeout either way -- ten seconds of
// nothing on every stop, every restart and every service shutdown, which is most of what
// made `conflux up` slow on Windows. Returning false lets the caller go straight to the
// kill it was always going to reach.
//
// Killing is safe for the reason the ordering in shutdown exists: `anchorctl stop` has
// already closed the anchor and said goodbye, so what is left is a daemon holding nothing.
// The graceful alternatives -- a named event anchord waits on, or a daemon-shutdown RPC --
// are anchord's to offer and it offers neither, so there is nothing better to send.
func terminate(cmd *exec.Cmd) bool {
	if cmd.Process == nil {
		return false
	}

	return windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(cmd.Process.Pid)) == nil
}
