package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"

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

	if err := mgr.Install(exe, "serve"); err != nil {
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

	report(d, cfg, st, "install")

	return ExitOK
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
		"  conflux install    start it again now\n" +
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
