package cli

import (
	"context"
	"errors"
	"flag"

	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/logfile"
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
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(ui.Errw)

	foreground := fs.Bool("foreground", false, "stay in the foreground even where a service manager is available")
	logPath := fs.String("log", "", "write the output to this file, each line stamped and the file moved aside to .1 past 10 MiB; "+
		"launchd's and FreeBSD's registrations pass it")

	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	// Where launchd or daemon(8) was told to write it: conflux writes it itself from here on,
	// stamping each line and moving it aside when it is full, which neither of them does.
	if *logPath != "" {
		if lf, err := logfile.Open(*logPath); err != nil {
			ui.Errf("could not open the log %s, so the output goes where the service manager sends it: %v", *logPath, err)
		} else {
			defer lf.Close()

			ui.Out, ui.Errw = lf, lf
		}
	}

	d := paths.Default()

	reconcileService(d)

	sup := &daemon.Supervisor{
		Dirs:     d,
		Reporter: reporter{},
		Ready:    make(chan struct{}),
		Drop:     true,
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
// Windows service, whose output is the log file.
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
