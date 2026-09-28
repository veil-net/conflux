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
// The bool is what lets shutdown tell "asked and waiting" from "never asked": false sends
// it to close the anchor over the socket with `anchorctl stop` and then kill a daemon
// holding nothing, rather than waiting out killTimeout on every stop, restart and service
// shutdown. The graceful alternatives -- a named event anchord waits on, or a
// daemon-shutdown RPC -- are anchord's to offer and it offers neither, so there is
// nothing better to send.
func terminate(cmd *exec.Cmd) bool {
	return windows.GenerateConsoleCtrlEvent(windows.CTRL_BREAK_EVENT, uint32(cmd.Process.Pid)) == nil
}
