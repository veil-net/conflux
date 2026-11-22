package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/libexec"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/ui"
)

// runUninstall is the reverse of everything conflux did here, and it destroys the identity: the
// boot service, every root -- configuration, identity, state, the extracted pairs, the service's copy
// of conflux, the log -- what an update left beside this conflux and the temporary copies of anchorctl
// killed readers left (removeLeftovers), and the accounts anchord ran as. Nothing is kept for a
// reinstall.
func runUninstall(_ context.Context, args []string) int {
	flags := flag.NewFlagSet("uninstall", flag.ContinueOnError)
	flags.SetOutput(ui.Errw)

	yes := flags.Bool("yes", false, "do not ask for confirmation")

	flags.Usage = func() {
		ui.Printf("conflux uninstall — remove everything conflux made here, the identity included\n\n" +
			"  conflux uninstall [--yes]\n\n" +
			"The boot service, the configuration, the credential and the state, the extracted\n" +
			"anchor binaries and the log. The credential has no other copy anywhere.\n")
	}

	if err := flags.Parse(args); err != nil {
		return ExitUsage
	}

	if err := needsRoot("removing the boot service", "uninstall", args); err != nil {
		return fail(err)
	}

	d := paths.Default()

	// What uninstall reads or signals by a name in a root -- the identity it asks about, the pid
	// record it stops anchord by -- it reads only where the root passes paths' check, as conflux makes
	// a root. A root that fails is removed all the same, reading nothing (paths.RemoveRoot), as itself
	// where it is a link.
	checked := d.Check()

	// An ephemeral run's account goes with the installation's, and nothing may be running as it when it
	// does: the run ends itself, with its anchor, when it is stopped. Asked before anything is asked, and
	// again once it is answered, before anything is removed. Nothing else of an ephemeral run's is
	// touched: its root is in the runtime folder, which the system empties at boot.
	if liveRefused() || !confirm(d, checked, *yes) || liveRefused() {
		return ExitUsage
	}

	// Each step tolerates its own failure: a half-removed installation must always be finishable,
	// so nothing stops at the first complaint. Remove stops the service on every platform before it
	// deregisters it, and removes what registering it wrote, a log outside the roots included.
	mgr := newService()

	var removed []string

	installed, _ := mgr.Installed()
	errs := []error{mgr.Remove()}

	if installed {
		removed = append(removed, "the boot service")
	}

	// Whatever anchord a supervisor that died left running out of the state directory, once the
	// service's own supervisor has let go of it.
	if checked == nil {
		reap(d, 35*time.Second)
	}

	gone, err := removeRoot(d.Root)
	errs = append(errs, err)

	if gone && err == nil {
		removed = append(removed, d.Root)
	}

	removed = append(removed, removeLeftovers()...)

	// The accounts anchord ran as, if conflux made them, stopping whatever runs as each: the ephemeral
	// run's unless one started since uninstall asked, which keeps it.
	e, started := liveEphemeral()
	if started {
		errs = append(errs, fmt.Errorf("an ephemeral run started from %s while conflux was being uninstalled, and "+
			"it was left running, with the account it runs as.\n  Stop it (Ctrl-C where it runs), then run this again",
			e.Root))
	}

	errs = append(errs, removeAccounts(!started))

	// What it removed, however far it got.
	if len(removed) > 0 {
		ui.Printf("Removed:\n")

		for _, r := range removed {
			ui.Printf("  %s\n", r)
		}

		ui.Println()
	}

	if err := errors.Join(errs...); err != nil {
		return fail(err)
	}

	ui.Printf("The boot service, the configuration, the identity and the state are gone, with everything else\n" +
		"conflux made. conflux up here again draws a new identity and a new overlay address.\n")

	return ExitOK
}

// reap is daemon.Reap, which a test counts.
var reap = daemon.Reap

// confirm is confirmUninstall, which a test answers, starting an ephemeral run as it is asked.
var confirm = confirmUninstall

// removeAccounts is removeAccount, which a test records.
var removeAccounts = removeAccount

// removeRoot is paths.RemoveRoot, which a test has fail with something at the root's name.
var removeRoot = paths.RemoveRoot

// liveRefused refuses uninstall while an ephemeral run is live, naming its root, and says whether it
// did.
func liveRefused() bool {
	e, live := liveEphemeral()
	if live {
		ui.Errf("an ephemeral anchor is running from %s.\n"+
			"  Stop it first (Ctrl-C where it runs): uninstall removes the account it runs as", e.Root)
	}

	return live
}

// removeLeftovers removes what earlier conflux left outside its root, uninstall's and tidy's alike, and
// is what it removed: what an update left beside this conflux (removeUpdateLeftovers), and the temporary
// copies of anchorctl readers killed before they removed them left (libexec.RemoveTemporary).
func removeLeftovers() []string {
	var removed []string

	if exe, err := updateExecutable(); err == nil {
		removed = removeUpdateLeftovers(exe)
	}

	return append(removed, libexec.RemoveTemporary()...)
}

// removeUpdateLeftovers removes what an update left beside exe, the conflux it replaced: a download
// that never went in place (update.Download's .conflux-update-*), and on Windows the image it moved
// aside (exe.old, which update.Replace makes there alone: elsewhere a file of that name is the
// operator's). Best effort: one still running is left -- on Windows the conflux an update ran from,
// which runs the new one's start or register, so its image goes at the next update, or uninstall.
// It returns what it removed.
func removeUpdateLeftovers(exe string) []string {
	removed := paths.RemovePrefixed(filepath.Dir(exe), ".conflux-update-", os.Remove)

	if runtime.GOOS == "windows" && os.Remove(exe+".old") == nil {
		removed = append(removed, exe+".old")
	}

	return removed
}

// confirmUninstall makes the irreversible part explicit before it happens: the identity. checked is
// what paths' check said of d's root: where it is not there there is nothing to destroy; where it
// failed, the identity in it is not read, and what is asked says why. It asks only where an identity is
// there, or may be; off a terminal, without yes, it refuses, so a scripted uninstall destroys none by
// default.
func confirmUninstall(d paths.Dirs, checked error, yes bool) bool {
	if yes || errors.Is(checked, fs.ErrNotExist) || checked == nil && !config.HasManifest(d) {
		return true
	}

	stakes := "deletes this machine's credential, and there is no other copy"

	if !ui.IsTerminal() {
		ui.Errf("this %s.\n  Pass --yes to say so explicitly; a scripted uninstall destroys nothing by default.", stakes)

		return false
	}

	ui.Printf("\nThis %s.\n\n", stakes)

	if checked != nil {
		ui.Field("anchor", "not read: "+checked.Error())
	} else if st, err := config.LoadState(d); err != nil {
		ui.Field("anchor", "unknown: "+err.Error())
	} else if st.AnchorID != "" {
		ui.Field("anchor", st.AnchorID)
	}

	ui.Printf("\nThe identity and the overlay address are gone. conflux up afterwards draws\n" +
		"new ones, and every machine that knew this one by its address will not find it.\n\n")

	return ui.Confirm("Continue?")
}
