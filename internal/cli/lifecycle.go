package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/privcheck"
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

	if err := privcheck.Require("registering the boot service", "conflux install"); err != nil {
		return fail(fmt.Errorf("%w: %w", errNeedsRoot, err))
	}

	return install(ctx, paths.Default(), true)
}

// install registers the service. standalone distinguishes `conflux install` typed by
// a person, which reports and may start, from the internal call `up` and `proxy`
// make, which is silent and leaves starting to the caller.
func install(ctx context.Context, d paths.Dirs, standalone bool) int {
	if err := d.EnsureAll(); err != nil {
		return fail(err)
	}

	mgr, err := service.New()
	if err != nil {
		return fail(err)
	}

	exe, err := service.Executable()
	if err != nil {
		return fail(err)
	}

	if warning := service.WarnIfEphemeral(exe); warning != "" {
		ui.Warnf("%s", warning)
	}

	// A CONFLUX_DIR run registers a service that has to come back to that same
	// directory. Passed as an argument rather than an environment variable because
	// none of the three service managers carries the operator's environment into
	// what it starts.
	serveArgs := []string{"serve"}
	if root := paths.Root(); root != "" {
		serveArgs = append(serveArgs, "--dir", root)
	}

	if err := mgr.Install(exe, serveArgs...); err != nil {
		if errors.Is(err, service.ErrUnsupported) {
			ui.Errf("%v", err)

			return ExitError
		}

		return fail(err)
	}

	if !standalone {
		return ExitOK
	}

	if _, err := config.Load(d); err != nil {
		if !os.IsNotExist(err) {
			return fail(err)
		}

		ui.Printf("The boot service is registered and will start at boot.\n" +
			"There is no configuration yet, so there is nothing to start now.\n\n" +
			"  conflux up                          join with a network interface\n" +
			"  conflux proxy 8080=127.0.0.1:3000   publish a port, no interface needed\n\n" +
			"Either writes the configuration and starts it.\n")

		return ExitOK
	}

	return startFromConfig(ctx, d, mgr, "install")
}

// startFromConfig starts the anchor this machine is already configured for.
//
// Shared by `install` and `start` so the two cannot drift into starting differently,
// the same argument daemon.BringUp makes for `up`, `proxy` and every boot. The caller
// has already established that a configuration exists and that the service is
// registered; this is only the starting.
func startFromConfig(ctx context.Context, d paths.Dirs, mgr service.Manager, verb string) int {
	ui.Printf("Starting from the configuration in %s.\n", d.ConfigFile())

	if err := mgr.Restart(); err != nil {
		return fail(err)
	}

	st, err := waitForAnchor(ctx, d)
	if err != nil {
		return fail(err)
	}

	cfg, err := config.Load(d)
	if err != nil {
		return fail(err)
	}

	report(d, cfg, st, verb)

	return ExitOK
}

// runStart starts the anchor now, from the configuration already on disk.
//
// The counterpart to down, and the reason it exists: down leaves the boot
// registration and the configuration in place, so there has to be a word for "bring
// that back now" that is not a reboot. That word used to be `conflux install`, whose
// name and usage line both say "register the boot service" -- it started one as a
// side effect, and pointing an operator at it was papering over a missing verb.
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

	if err := privcheck.Require("starting the service", "conflux start"); err != nil {
		return fail(fmt.Errorf("%w: %w", errNeedsRoot, err))
	}

	d := paths.Default()

	mgr, err := service.New()
	if err != nil {
		return fail(err)
	}

	installed, err := mgr.Installed()
	if err != nil {
		return fail(err)
	}

	// Like down, start is defined against an installed service. Registering one here
	// would be install's job done quietly, and a machine that gained a boot service
	// because somebody typed "start" is a surprise at the next reboot rather than now.
	if !installed {
		ui.Errf("conflux is not installed here, so there is no service to start.\n\n" +
			"  conflux install    register the boot service, and start it if configured\n" +
			"  conflux up         join with a network interface\n" +
			"  conflux proxy 8080=127.0.0.1:3000   publish a port, no interface needed")

		return ExitUnavailable
	}

	// The same 78 the supervisor exits with, and for the same reason: there is a
	// service here and nothing for it to run.
	if _, err := config.Load(d); err != nil {
		if !os.IsNotExist(err) {
			return fail(err)
		}

		ui.Errf("There is no configuration on this machine, so there is nothing to start.\n\n" +
			"  conflux up                          join with a network interface\n" +
			"  conflux proxy 8080=127.0.0.1:3000   publish a port, no interface needed")

		return ExitNoConfig
	}

	// No check for "already running". mgr.Restart covers both, and a start that
	// refused a running anchor would be answering a question nobody asked -- the
	// caller wants it up, and it ends up up.
	return startFromConfig(ctx, d, mgr, "start")
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

	if err := privcheck.Require("stopping the service", "conflux down"); err != nil {
		return fail(fmt.Errorf("%w: %w", errNeedsRoot, err))
	}

	mgr, err := service.New()
	if err != nil {
		return fail(err)
	}

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

	ui.Printf("Stopped. The boot service is still registered and the configuration is intact,\n" +
		"so the next reboot brings this machine back exactly as it was.\n\n" +
		"  conflux start      start it again now\n" +
		"  conflux uninstall  remove it permanently\n")

	return ExitOK
}

// runUninstall is the reverse of install, and it destroys the identity.
func runUninstall(_ context.Context, args []string) int {
	fs := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	fs.SetOutput(ui.Errw)

	yes := fs.Bool("yes", false, "do not ask for confirmation")

	fs.Usage = func() {
		ui.Printf("conflux uninstall — remove the boot service, the configuration and the identity\n\n" +
			"  conflux uninstall [--yes]\n\n" +
			"This deletes the credential, and there is no other copy of it anywhere.\n")
	}

	if err := fs.Parse(args); err != nil {
		return ExitUsage
	}

	if err := privcheck.Require("removing the boot service", "conflux uninstall"); err != nil {
		return fail(fmt.Errorf("%w: %w", errNeedsRoot, err))
	}

	d := paths.Default()

	if !confirmUninstall(d, *yes) {
		return ExitUsage
	}

	mgr, err := service.New()
	if err != nil {
		return fail(err)
	}

	// Each step tolerates its own failure: a half-removed installation must always
	// be finishable, and stopping at the first complaint is what made that
	// impossible in the previous conflux.
	_ = mgr.Stop()

	var first error

	if err := mgr.Remove(); err != nil && !errors.Is(err, service.ErrUnsupported) {
		first = err
	}

	for _, dir := range []string{d.Run, d.State, d.Config} {
		if dir == "" {
			continue
		}

		if err := os.RemoveAll(dir); err != nil && first == nil {
			first = err
		}
	}

	if first != nil {
		return fail(first)
	}

	ui.Printf("Removed. The boot service, the configuration and the identity are gone.\n" +
		"conflux up here again draws a new identity and a new overlay address.\n")

	return ExitOK
}

// confirmUninstall makes the irreversible part explicit before it happens.
func confirmUninstall(d paths.Dirs, yes bool) bool {
	if !config.HasManifest(d) {
		return true
	}

	st, _ := config.LoadState(d)

	if yes {
		return true
	}

	if !ui.IsTerminal() {
		ui.Errf("this deletes the credential and there is no other copy.\n" +
			"  Pass --yes to say so explicitly; a scripted uninstall will not destroy an identity by default.")

		return false
	}

	ui.Printf("\nThis deletes this machine's credential, and there is no other copy.\n\n")

	if st.AnchorID != "" {
		ui.Field("anchor", st.AnchorID)
	}

	ui.Printf("\nThe identity and the overlay address are gone. conflux up afterwards draws\n" +
		"new ones, and every machine that knew this one by its address will not find it.\n\n")

	return ui.Confirm("Continue?")
}
