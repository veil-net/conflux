//go:build !windows

package cli

import (
	"context"
	"os"
	"os/exec"
	"os/signal"

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

		return ExitError
	}

	return ExitOK // unreachable: Exec does not return on success
}

// runForwarding runs cmd, a child conflux waits for in place of replacing itself with it, and
// passes it the SIGTERM this process is sent, from before it starts until it exits: Main's
// context takes it from conflux, which would otherwise go on waiting for a child that nothing
// told to end. SIGINT is taken too, so that it does not end conflux before its child, and not
// passed on: a terminal's Ctrl-C reaches the whole foreground process group, the child with it,
// and passed on as well it would arrive twice.
func runForwarding(cmd *exec.Cmd) error {
	term, intr := make(chan os.Signal, 1), make(chan os.Signal, 1)
	signal.Notify(term, unix.SIGTERM)
	signal.Notify(intr, os.Interrupt)

	defer signal.Stop(intr)
	defer signal.Stop(term)

	if err := cmd.Start(); err != nil {
		return err
	}

	exited := make(chan struct{})
	defer close(exited)

	go func() {
		for {
			select {
			case s := <-term:
				_ = cmd.Process.Signal(s)
			case <-exited:
				return
			}
		}
	}()

	return cmd.Wait()
}
