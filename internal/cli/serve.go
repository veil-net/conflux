package cli

import (
	"context"
	"errors"
	"flag"
	"os"

	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/ui"
)

// runServe is the supervisor: the process the service manager actually runs.
//
// Hidden from help because it is not something to type. On Windows it hands over to
// the service control manager when it detects it is running as a service, and runs
// in the foreground otherwise.
func runServe(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(ui.Errw)

	foreground := fs.Bool("foreground", false, "stay in the foreground even where a service manager is available")
	dir := fs.String("dir", "", "root every conflux path here, as CONFLUX_DIR does; the service registration passes it back")

	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	// A service registered from a CONFLUX_DIR run has to come back to the same
	// directory, and an environment variable does not survive the trip: systemd
	// gives a unit a clean environment, launchd the same, and an SCM service
	// inherits the system environment rather than the operator's. So install writes
	// the root into the argv it registers, and this is where it is picked back up.
	//
	// Through the environment rather than by threading a Dirs everywhere, so that
	// every paths.Default in this process agrees with this one. Before anything
	// starts, so there is no goroutine to race.
	if *dir != "" {
		if err := os.Setenv("CONFLUX_DIR", *dir); err != nil {
			return fail(err)
		}
	}

	d := paths.Default()

	sup := &daemon.Supervisor{
		Dirs:     d,
		Reporter: reporter{},
		Ready:    make(chan struct{}),
	}

	if !*foreground {
		if handled, code := serveAsService(sup); handled {
			return code
		}
	}

	return runSupervisor(ctx, sup)
}

func runSupervisor(ctx context.Context, sup *daemon.Supervisor) int {
	notifyReadyWhen(sup.Ready)

	err := sup.Run(ctx)

	switch {
	case err == nil:
		return ExitOK
	case errors.Is(err, daemon.ErrNotConfigured):
		// Exit 78 and not 1. The systemd unit names this number in
		// RestartPreventExitStatus, so a registered service on a machine with no
		// configuration stops here instead of restarting every five seconds until
		// somebody notices the journal.
		ui.Errf("there is no configuration to start.\n" +
			"  conflux up      join with a network interface\n" +
			"  conflux proxy   publish a port, no interface needed")

		return ExitNoConfig
	default:
		ui.Errf("%v", err)

		return ExitChildFailed
	}
}
