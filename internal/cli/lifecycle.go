package cli

import (
	"context"
	"errors"
	"flag"
	"os"
	"strings"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/service"
	"github.com/veil-net/conflux/internal/ui"
)

// runInstall registers the boot service, and nothing else.
//
// This is the minimal building block: `up` and `proxy` call it after writing their
// configuration, so there is one code path for "register and run" and one for
// "configure, persist, then register and run". Run on its own with no configuration
// it registers the service, says plainly that there is nothing to start, and exits
// zero -- it did what it was asked. No configuration is invented.
func runInstall(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("install", flag.ContinueOnError)
	fs.SetOutput(ui.Errw)
	fs.Usage = func() {
		ui.Printf("conflux install — register the boot service\n\n" +
			"  conflux install\n\n" +
			"Registers the service so this machine rejoins at boot. If a configuration\n" +
			"already exists it is also started; if not, nothing is invented.\n")
	}

	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	if err := needsRoot("registering the boot service", "install", args); err != nil {
		return fail(err)
	}

	d := paths.Default()
	if err := d.EnsureAll(); err != nil {
		return fail(err)
	}

	return install(ctx, d, true, service.Place)
}

// runRegister places this conflux's copy for the boot service and registers the service
// as this conflux defines it, and starts nothing: install's silent half, which `update` has
// the conflux it put in place run when the anchor is stopped, so the new conflux writes
// its own definition, as the new conflux's `start` does when the anchor is running. Before it
// places anything it removes what earlier conflux left (tidy), and writes the copy afresh; a
// supervisor that still served the root without an anchor, which tidy stops, is started
// again, on this conflux, however register ends (startAgain).
func runRegister(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("register", flag.ContinueOnError)
	fs.SetOutput(ui.Errw)
	fs.Usage = func() {
		ui.Printf("conflux register — register the boot service on this conflux, and start nothing\n\n" +
			"  conflux register\n\n" +
			"conflux update runs it in the conflux it put in place.\n")
	}

	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	if fs.NArg() > 0 {
		ui.Errf("conflux register takes no arguments, and got %q.", fs.Arg(0))

		return ExitUsage
	}

	if err := needsRoot("registering the boot service", "register", args); err != nil {
		return fail(err)
	}

	// tidy makes the roots as conflux makes them (EnsureAll).
	d := paths.Default()
	mgr := newService()

	stopped, err := tidy(d, mgr)
	if err != nil {
		return startAgain(mgr, stopped, fail(err))
	}

	return startAgain(mgr, stopped, install(ctx, d, false, service.PlaceAfresh))
}

// startAgain starts the service tidy stopped, where it stopped it, once the command it stopped it for
// has come to code, and is code: a failure to start it fails a command that had not failed, and is
// warned of beside one that had, which leaves the service as it was found, serving the root.
func startAgain(mgr service.Manager, stopped bool, code int) int {
	if !stopped {
		return code
	}

	err := mgr.Restart()

	switch {
	case err == nil:
		return code
	case code == ExitOK:
		return fail(err)
	}

	ui.Errf("the boot service, stopped to remove what earlier conflux left, did not start again: %v", err)

	return code
}

// install places the copy of conflux the service runs, with place, and registers it. standalone
// distinguishes `conflux install` typed by a person, which reports and may start, from the
// internal call `up`, `proxy` and `observe` make, and `start` and `register`, which is
// silent and leaves starting to the caller. Each has its directories already. place is
// service.Place, which copies this conflux where the copy differs; service.PlaceAfresh, which writes
// it whatever is there, for an update, once tidy has cleared what earlier conflux left; or keep, for
// a copy service.Placed has found to be this conflux already.
//
// The readiness marker is withdrawn first, before anything that can start the service --
// launchd's Install does, for a running job whose definition changed -- and nothing
// withdraws it after. Every path that restarts the service and waits for it comes through
// here, so the marker waitFor sees can only have been written by a supervisor started
// since: one the outgoing supervisor left would let it report an anchor seconds from being
// torn down, and one withdrawn after a start would leave it nothing to see but a status
// call once a second.
func install(ctx context.Context, d paths.Dirs, standalone bool, place func(paths.Dirs) (string, error)) int {
	mgr := newService()

	if err := daemon.ClearReady(d); err != nil {
		// Not fatal. A marker that will not go costs waitFor one status call it was going
		// to make anyway, which is exactly what the fallback is for.
		ui.Errf("could not clear the readiness marker: %v", err)
	}

	exe, err := place(d)
	if err != nil {
		return fail(err)
	}

	if err := register(mgr, exe); err != nil {
		return fail(err)
	}

	if !standalone {
		return ExitOK
	}

	cfg, err := config.Load(d)
	if err != nil {
		if !os.IsNotExist(err) {
			return fail(err)
		}

		ui.Printf("The boot service is registered and will start at boot.\n" +
			"There is no configuration yet, so there is nothing to start now.\n\n" +
			configureHint + "\n\n" +
			"Each writes the configuration and starts it.\n")

		return ExitOK
	}

	return startFromConfig(ctx, d, mgr, cfg, "install")
}

// keep is install's place for a copy service.Placed has found to be this conflux, which is not
// compared again (service.Keep).
func keep(d paths.Dirs) (string, error) { return service.Keep(d), nil }

// newService is the boot manager install registers with, start and update ask about,
// startAndReport restarts and names, status names, down stops, and uninstall removes; a test's
// stands in for it.
var newService = service.New

// register names exe, the copy Place made, as the boot service, defined as this conflux
// defines it: an upgraded conflux's definition reaches the service the next time it is
// placed. Nothing at all when the definition is the one already there.
func register(mgr service.Manager, exe string) error {
	// A CONFLUX_DIR run registers a service that has to come back to that same
	// directory. Passed as an argument rather than an environment variable because
	// none of the three service managers carries the operator's environment into
	// what it starts.
	serveArgs := []string{"serve"}
	if root := paths.Root(); root != "" {
		serveArgs = append(serveArgs, "--dir", root)
	}

	return mgr.Install(exe, serveArgs...)
}

// startFromConfig starts the anchor this machine is already configured for.
//
// Shared by `install` and `start` so the two cannot drift into starting differently,
// the same argument the daemon's one bring-up makes for `up`, `proxy` and every boot. The caller
// has already established that a configuration exists and that the service is
// registered; this is only the starting.
func startFromConfig(ctx context.Context, d paths.Dirs, mgr service.Manager, cfg *config.Config, verb string) int {
	ui.Printf("Starting from the configuration in %s.\n", d.ConfigFile())

	return startAndReport(ctx, d, mgr, cfg, verb)
}

// runStart starts the anchor now, from the configuration already on disk.
//
// The counterpart to down, and the reason it exists: down leaves the boot
// registration and the configuration in place, so there has to be a word for "bring
// that back now" that is not a reboot.
//
// Mode-agnostic on purpose. `up` would do for a TUN machine, but it is not a resume:
// it re-decides the configuration, and on a userspace machine it changes the mode and
// drops the proxies. A machine serving eight ports cannot be brought back by retyping
// eight specs correctly from memory.
func runStart(ctx context.Context, args []string) int {
	fs := flag.NewFlagSet("start", flag.ContinueOnError)
	fs.SetOutput(ui.Errw)
	fs.Usage = func() {
		ui.Printf("conflux start — start the anchor now, from the saved configuration\n\n" +
			"  conflux start\n\n" +
			"The counterpart to conflux down. Starts whatever this machine is already\n" +
			"configured for, in whichever mode it names, and asks nothing. Nothing is\n" +
			"enrolled and no configuration is invented.\n")
	}

	// anchorctl has a start of its own, and it is the one that takes flags: it
	// builds an anchor from arguments the caller supplies. conflux's starts the one
	// its configuration already describes, which is the whole difference and the
	// reason it takes none. Resolve by shape, the way renew does.
	if hint := anchorctlFlag(args); hint != "" {
		ui.Errf("%q is anchorctl's start, not conflux's.\n\n"+
			"  conflux start starts the anchor this machine is already configured for:\n\n"+
			"    conflux start\n\n"+
			"  To build an anchor from arguments of your own, that is anchorctl's, one word away:\n\n"+
			"    conflux anchorctl start %s", hint, strings.Join(args, " "))

		return ExitUsage
	}

	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	if fs.NArg() > 0 {
		ui.Errf("conflux start takes no arguments, and got %q.\n\n"+
			"  conflux start", fs.Arg(0))

		return ExitUsage
	}

	if err := needsRoot("starting the service", "start", args); err != nil {
		return fail(err)
	}

	d := paths.Default()

	mgr := newService()

	installed, err := mgr.Installed()
	if err != nil {
		return fail(err)
	}

	// Like down, start is defined against an installed service. Registering one here
	// would be install's job done quietly, and a machine that gained a boot service
	// because somebody typed "start" is a surprise at the next reboot rather than now.
	if !installed {
		ui.Errf("conflux is not installed here, so there is no service to start.\n\n" +
			"  conflux install                     register the boot service, and start it if configured\n" +
			configureHint)

		return ExitUnavailable
	}

	// The service runs its own copy of conflux, and this one may be newer: replacing the binary and
	// typing start is how an upgrade reaches the service -- the copy, and the definition the service
	// is registered with, which a newer conflux may write differently -- and it is how update hands a
	// running service over. Where the copy is not this conflux, or the roots fail the readers' check,
	// so that it is not read to find out, what earlier conflux left goes first, the service stopped for
	// it (tidy), and the copy is written afresh below; the restart after starts it again, on this one.
	//
	// Either way the roots are made as conflux makes them, as the service makes them at every start,
	// before anything in them is read by its name, placed there or registered (EnsureAll, which tidy
	// runs); with a service registered, roots not there are made, as that service would make them.
	checked := d.Check()
	afresh := checked == nil && !service.Placed(d) || checked != nil && !errors.Is(checked, os.ErrNotExist)

	// The service tidy stopped is started again however start ends: by startFromConfig's restart, or
	// before (startAgain). A copy Placed found to be this conflux is not compared again as it is
	// placed.
	stopped := false
	place := service.PlaceAfresh

	if afresh {
		var err error
		if stopped, err = tidy(d, mgr); err != nil {
			return startAgain(mgr, stopped, fail(err))
		}
	} else {
		if err := d.EnsureAll(); err != nil {
			return fail(err)
		}

		place = service.Place
		if checked == nil {
			place = keep
		}
	}

	// The same 78 the supervisor exits with, and for the same reason: there is a
	// service here and nothing for it to run.
	cfg, err := config.Load(d)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return startAgain(mgr, stopped, fail(err))
		}

		ui.Errf("There is no configuration on this machine, so there is nothing to start.\n\n" + configureHint)

		return startAgain(mgr, stopped, ExitNoConfig)
	}

	if code := install(ctx, d, false, place); code != ExitOK {
		return startAgain(mgr, stopped, code)
	}

	// No check for "already running". mgr.Restart covers both, and a start that
	// refused a running anchor would be answering a question nobody asked -- the
	// caller wants it up, and it ends up up.
	return startFromConfig(ctx, d, mgr, cfg, "start")
}

// runDown stops the anchor now and leaves everything else alone.
//
// The whole distinction from uninstall is in what it does not touch: the boot
// registration stays, the configuration stays, the identity stays. The next reboot
// brings the machine back exactly as it was, with nothing typed.
func runDown(_ context.Context, args []string) int {
	fs := flag.NewFlagSet("down", flag.ContinueOnError)
	fs.SetOutput(ui.Errw)
	fs.Usage = func() {
		ui.Printf("conflux down — stop the anchor now; a reboot brings it back\n\n" +
			"  conflux down\n\n" +
			"Leaves the boot service registered and the configuration in place. To remove\n" +
			"those as well, that is conflux uninstall.\n")
	}

	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	if err := needsRoot("stopping the service", "down", args); err != nil {
		return fail(err)
	}

	// The record of an anchor given up on is cleared by its name in the state directory, so the
	// roots pass paths' check first; one not there holds no record.
	d := paths.Default()

	checked := d.Check()
	if checked != nil && !errors.Is(checked, os.ErrNotExist) {
		return fail(checked)
	}

	mgr := newService()

	installed, err := mgr.Installed()
	if err != nil {
		return fail(err)
	}

	// down is defined against an installed service. Without one there is nothing
	// for a reboot to bring back, so the word would be a lie.
	if !installed {
		ui.Errf("conflux is not installed here, so there is nothing to bring back afterwards.\n\n" +
			"  conflux status     what this machine thinks it is doing\n" +
			"  conflux install    register the boot service\n" +
			"  conflux up         join, and register it")

		return ExitUnavailable
	}

	if err := mgr.Stop(); err != nil {
		return fail(err)
	}

	// An anchor stopped by hand is not one the supervisor gave up on, so status says no more of
	// that than of anything else the stopped service ran.
	if checked == nil {
		if err := daemon.ForgetRefusal(d); err != nil {
			ui.Errf("could not clear the record of the anchor the supervisor gave up on: %v", err)
		}
	}

	ui.Printf("Stopped. The boot service is still registered and the configuration is intact,\n" +
		"so the next reboot brings this machine back exactly as it was.\n\n" +
		"  conflux start      start it again now\n" +
		"  conflux uninstall  remove it permanently\n")

	return ExitOK
}
