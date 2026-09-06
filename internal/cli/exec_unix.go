//go:build !windows

package cli

import (
	"context"

	"golang.org/x/sys/unix"

	"github.com/veil-net/conflux/internal/ui"
)

// execAnchorctl replaces this process with anchorctl.
//
// Replacing rather than spawning is the difference between a wrapper and a
// forwarder. There is no second process to keep alive, no exit code to translate,
// no signal to relay and no pipe to pump -- the terminal is talking to anchorctl
// directly, and conflux is gone.
func execAnchorctl(_ context.Context, bin string, args []string, env []string) int {
	argv := append([]string{"anchorctl"}, args...)

	if err := unix.Exec(bin, argv, env); err != nil {
		ui.Errf("could not run %s: %v", bin, err)

		return ExitChildFailed
	}

	return ExitOK // unreachable: Exec does not return on success
}
