//go:build windows

package daemon

import (
	"errors"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

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

// kill ends anchord outright.
func kill(cmd *exec.Cmd) { _ = cmd.Process.Kill() }

// killJob is the job every anchord this supervisor starts is put in. Closing it ends
// them, and the system closes it when this process ends, however it ends: the SCM
// terminating the service after its stop timeout, or a crash, takes anchord with it
// rather than leaving it holding the socket.
var killJob = sync.OnceValues(newKillJob)

func newKillJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}

	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{
		BasicLimitInformation: windows.JOBOBJECT_BASIC_LIMIT_INFORMATION{
			LimitFlags: windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
		},
	}

	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		_ = windows.CloseHandle(job)

		return 0, err
	}

	return job, nil
}

// bind puts anchord in killJob.
func bind(p *os.Process) error {
	job, err := killJob()
	if err != nil {
		return err
	}

	return assign(job, p)
}

func assign(job windows.Handle, p *os.Process) error {
	h, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(p.Pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)

	return windows.AssignProcessToJobObject(job, h)
}

// alive reports whether a process with this pid is still running.
func alive(pid int) bool {
	h, err := windows.OpenProcess(windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return false
	}
	defer windows.CloseHandle(h)

	event, err := windows.WaitForSingleObject(h, 0)

	return err == nil && event == uint32(windows.WAIT_TIMEOUT)
}

// stopOrphan ends an anchord this process did not start. Nothing gentler reaches a
// daemon from a service on Windows; see terminate.
func stopOrphan(pid int) error {
	h, err := windows.OpenProcess(windows.PROCESS_TERMINATE|windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)

	if err := windows.TerminateProcess(h, 1); err != nil {
		return err
	}

	if event, err := windows.WaitForSingleObject(h, 5000); err != nil || event != windows.WAIT_OBJECT_0 {
		return errors.New("it did not exit after it was terminated")
	}

	return nil
}

// processExe is the executable a process runs.
func processExe(pid int) (string, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))

	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return "", err
	}

	return windows.UTF16ToString(buf[:n]), nil
}
