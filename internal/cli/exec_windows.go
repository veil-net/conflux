//go:build windows

package cli

import (
	"context"
	"os/exec"
)

// execAnchorctl runs anchorctl as a child and exits with its code.
//
// Windows has no execve, so this is the closest available: runAnchorctl.
func execAnchorctl(_ context.Context, bin string, args []string, env []string) int {
	return runAnchorctl(bin, args, env)
}

// runForwarding runs cmd. The console gives a Ctrl+C to every process attached to it, the
// child's included, and Windows has no SIGTERM for conflux to pass on.
func runForwarding(cmd *exec.Cmd) error { return cmd.Run() }
