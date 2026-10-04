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
// console is genuinely shared, and the child's exit code passed back verbatim. Not tied
// to the context, which Ctrl+C cancels: the console delivers that to anchorctl as well,
// and it ends on its own terms, as it would had it replaced this process.
func execAnchorctl(_ context.Context, bin string, args []string, env []string) int {
	cmd := exec.Command(bin, args...)
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
