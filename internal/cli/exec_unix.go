//go:build !windows

package cli

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"slices"
	"syscall"
	"time"

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

// runForwarding runs cmd to its end, passing each forwarded signal conflux catches on to it,
// and calls done, where it is given, once it has ended, still forwarding, so no signal ends
// conflux before done has run. Ctrl+C at the terminal reaches anchorctl from the terminal as
// well, as a second SIGINT.
func runForwarding(cmd *exec.Cmd, done func()) error {
	// Before the start, so a signal sent from here on is held until it can be passed on. Each is
	// named alone: Notify naming none would relay every signal.
	sigs := make(chan os.Signal, len(forwarded))
	for _, s := range forwarded {
		if catches(s) {
			signal.Notify(sigs, s)
		}
	}

	defer signal.Stop(sigs)

	if done != nil {
		defer done()
	}

	if err := cmd.Start(); err != nil {
		return err
	}

	ended := make(chan error, 1)
	go func() { ended <- cmd.Wait() }()

	for {
		select {
		case s := <-sigs:
			_ = cmd.Process.Signal(s)
		case err := <-ended:
			return err
		}
	}
}

// exitStatus is how conflux ends for an anchorctl that ended so: with its exit code, or, ended
// by a forwarded signal, by that signal -- which Go's runtime ends a process by once nothing
// listens for it -- so whatever waits on conflux sees what it would have seen of anchorctl had
// conflux replaced itself with it: a shell stops a script on a SIGINT that ended its child, and
// not on an exit code. Any other signal is reported as a shell reports one, 128 and its number.
func exitStatus(ps *os.ProcessState) int {
	ws, ok := ps.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() {
		return ps.ExitCode()
	}

	sig := ws.Signal()

	if slices.Contains(forwarded, os.Signal(sig)) {
		signal.Reset(sig)

		// Delivery is asynchronous: it ends the process here. A signal this process was
		// started ignoring, as nohup starts it ignoring SIGHUP, is ignored still.
		if syscall.Kill(os.Getpid(), sig) == nil {
			time.Sleep(time.Second)
		}
	}

	return 128 + int(sig)
}
