//go:build windows

package cli

import (
	"context"
	"os"
	"os/exec"
)

// execAnchorctl runs anchorctl as a child and exits with its code.
//
// Windows has no execve, so this is the closest available: runAnchorctl.
func execAnchorctl(_ context.Context, bin string, args []string, env []string) int {
	return runAnchorctl(bin, args, env, nil)
}

// runForwarding runs cmd to its end, and calls done, where it is given, once it has ended.
// Nothing is passed on: Windows sends a process no signal of its own, and what a console sends
// -- Ctrl+C, Ctrl+Break, its closing, a logoff, a shutdown -- reaches every process attached to
// it, anchorctl among them, which shares conflux's. Only a process ended outright
// (TerminateProcess: taskkill /F, Stop-Process) ends without anchorctl.
func runForwarding(cmd *exec.Cmd, done func()) error {
	if done != nil {
		defer done()
	}

	return cmd.Run()
}

// exitStatus is anchorctl's exit code, which conflux ends with.
func exitStatus(ps *os.ProcessState) int { return ps.ExitCode() }
