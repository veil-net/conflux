package cli

import (
	"errors"
	"os"
	"os/exec"
	"syscall"

	"github.com/veil-net/conflux/internal/ui"
)

// forwarded are the signals that end a process. On Unix conflux passes each on to the anchorctl
// it runs as a child (runForwarding): sent to conflux's PID alone -- by kill, a service manager
// stopping it, a hangup -- they would otherwise end conflux, or be caught by it, and leave
// anchorctl running. Once an ephemeral run's first has stopped it, the next ends conflux at once
// (secondSignalEnds).
var forwarded = []os.Signal{syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT}

// runAnchorctl runs anchorctl as a child and ends as it ends: what Windows does in place of
// execve, and what usage and a socket the user named do everywhere, since each waits to remove
// a temporary copy afterwards. done is that removal, made once the child has ended, or failed
// to start, before anything else.
//
// Inherited handles, so the console is genuinely shared, and the child's exit code passed
// back verbatim. Not tied to a context, which Ctrl+C cancels: the terminal delivers that to
// anchorctl as well, and it ends on its own terms, as it would had it replaced this process.
// What is sent to conflux's PID alone is passed on (runForwarding), so nothing conflux runs
// outlives it, and a child a signal ended is reported by that signal (exitStatus).
func runAnchorctl(bin string, args []string, env []string, done func()) int {
	cmd := exec.Command(bin, args...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := runForwarding(cmd, done); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return exitStatus(ee.ProcessState)
		}

		ui.Errf("could not run %s: %v", bin, err)

		return ExitError
	}

	return ExitOK
}
