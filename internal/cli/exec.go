package cli

import (
	"errors"
	"os"
	"os/exec"

	"github.com/veil-net/conflux/internal/ui"
)

// anchorctlExec and anchorctlRun are how a pass-through hands over to anchorctl: in place of
// this process, or as a child it waits for. Variables, so a test drives a pass-through to its
// end without running one.
var anchorctlExec, anchorctlRun = execAnchorctl, runAnchorctl

// runAnchorctl runs anchorctl as a child and returns its exit code: what Windows does in
// place of execve, and what a temporary copy of anchorctl does everywhere, since conflux waits
// to remove it afterwards.
//
// Inherited handles, so the console is genuinely shared, and the child's exit code passed
// back verbatim. Not tied to a context, which Ctrl+C cancels: anchorctl is given the signal
// and ends on its own terms, as it would had it replaced this process -- a Ctrl+C by the
// console or the terminal, which give it to the child as well, and on Unix a SIGTERM by
// runForwarding, which passes on the one conflux is sent.
func runAnchorctl(bin string, args []string, env []string) int {
	cmd := exec.Command(bin, args...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := runForwarding(cmd); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return ee.ExitCode()
		}

		ui.Errf("could not run %s: %v", bin, err)

		return ExitError
	}

	return ExitOK
}
