//go:build windows

package cli

import (
	"context"
	"errors"
	"os"
	"os/exec"

	"github.com/veil-net/conflux/internal/ui"
)

// execAnchorctl runs anchorctl as a child and exits with its code.
//
// Windows has no execve, so this is the closest available: inherited handles so the
// console is genuinely shared, and the child's exit code passed back verbatim.
func execAnchorctl(ctx context.Context, bin string, args []string, env []string) int {
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}

		ui.Errf("could not run %s: %v", bin, err)

		return ExitChildFailed
	}

	return ExitOK
}
