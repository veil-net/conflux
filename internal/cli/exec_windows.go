//go:build windows

package cli

import "context"

// execAnchorctl runs anchorctl as a child and exits with its code.
//
// Windows has no execve, so this is the closest available: runAnchorctl.
func execAnchorctl(_ context.Context, bin string, args []string, env []string) int {
	return runAnchorctl(bin, args, env)
}
