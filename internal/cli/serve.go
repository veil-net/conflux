package cli

import (
	"context"
	"errors"
	"flag"

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

	if err := fs.Parse(args); err != nil {
		return ExitUsage
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
