package cli

import (
	"context"
	"errors"

	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/privcheck"
	"github.com/veil-net/conflux/internal/service"
	"github.com/veil-net/conflux/internal/ui"
)

// runServe is the supervisor: the process the service manager actually runs.
//
// Hidden from help because it is not something to type. On Windows it hands over to
// the service control manager when it detects it is running as a service, and runs
// in the foreground otherwise.
func runServe(ctx context.Context, args []string) int {
	fs := verbFlags("serve", "conflux serve — run the supervisor in the foreground\n\n"+
		"  conflux serve [--foreground]\n\n"+
		"What the boot service runs, and nothing to type: conflux start starts it.\n\n")

	foreground := fs.Bool("foreground", false, "stay in the foreground even where a service manager is available")

	if err := fs.Parse(args); err != nil {
		return usageExit(err)
	}

	// Where launchd started it, which keeps no output, to the system log.
	toSystemLog()

	d := paths.Default()

	sup := &daemon.Supervisor{
		Dirs:     d,
		Reporter: reporter{},
		Ready:    make(chan struct{}),
		Drop:     true,
		// Once serve.lock is held, so a second supervisor, refused, changes nothing; on
		// Windows that is also once the output goes to the Event Log, which records a failure.
		Reconcile: func() { reconcileService(d) },
	}

	if !*foreground {
		if handled, code := serveAsService(sup); handled {
			return code
		}
	}

	return launchdExit(runSupervisor(ctx, sup))
}

// reconcileService puts the boot service back to what this conflux registers -- the copy it
// runs, placed in the root, and its definition -- wherever either was changed since: the
// service is the supervisor's to keep, as the root is. Nothing when no service is registered
// (a supervisor run by hand), or when this is not root. A failure is said and costs no start.
func reconcileService(d paths.Dirs) {
	if !privcheck.Elevated() {
		return
	}

	mgr := services()

	if installed, err := mgr.Installed(); err != nil || !installed {
		return
	}

	exe, err := service.Place(d)
	if err == nil {
		err = mgr.Reconcile(exe, "serve")
	}

	if err != nil {
		ui.Errf("could not put the boot service back to what this conflux registers: %v", err)
	}
}

func runSupervisor(ctx context.Context, sup *daemon.Supervisor) int {
	notifyReadyWhen(sup.Ready)

	return supervisorExit(sup.Run(ctx))
}

// supervisorExit says why the supervisor ended, and picks the exit status that tells the
// service manager whether to start it again. Shared by the foreground run and the
// Windows service, whose output is the Event Log.
func supervisorExit(err error) int {
	switch {
	case err == nil:
		return ExitOK
	case errors.Is(err, daemon.ErrNotConfigured):
		// Exit 78 and not 1. The systemd unit names this number in
		// RestartPreventExitStatus, so a registered service on a machine with no
		// configuration stops here instead of restarting every five seconds until
		// somebody notices the journal.
		ui.Errf("there is no configuration to start.\n" + configureHint)

		return ExitNoConfig
	case daemon.Permanent(err):
		ui.Errf("%v", err)

		return ExitChildFailed
	default:
		// Not 70: a failure the next start may not meet -- extraction on a full disk, a
		// token that could not be written -- so systemd, launchd and the Windows SCM are
		// left to restart it. The BSDs' rc does not; see docs/service.md.
		ui.Errf("%v", err)

		return ExitError
	}
}
