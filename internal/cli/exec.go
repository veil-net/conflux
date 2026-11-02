package cli

import (
	"errors"
	"os"
	"os/exec"

	"github.com/veil-net/conflux/internal/ui"
)

// runAnchorctl runs anchorctl as a child and returns its exit code: what Windows does in
// place of execve, and what usage does everywhere, since it waits to remove a temporary
// copy afterwards.
//
// Inherited handles, so the console is genuinely shared, and the child's exit code passed
// back verbatim. Not tied to a context, which Ctrl+C cancels: the terminal delivers that to
// anchorctl as well, and it ends on its own terms, as it would had it replaced this process.
func runAnchorctl(bin string, args []string, env []string) int {
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

		return ExitError
	}

	return ExitOK
}
