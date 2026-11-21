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
	"slices"
	"strings"
	"time"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/flock"
	"github.com/veil-net/conflux/internal/logfile"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/ui"
)

// runUninstall is the reverse of everything conflux did here, and it destroys the identity: the
// boot service, every root -- configuration, identity, state, the extracted pairs, the service's copy
// of conflux, the log -- the ephemeral runs' roots, what an update left beside this conflux, and the
// accounts anchord ran as. Nothing is kept for a reinstall.
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
	// record it stops anchord by -- it reads only where the root passes paths' check, since whoever
	// could change the root could have put theirs there. A root that fails is removed all the same,
	// reading nothing (paths.RemoveRoot): nothing in it is followed, and a CONFLUX_DIR's way is held
	// to parents' rule as it is removed, so nothing can lead the removal elsewhere.
	checked := d.Check()

	// The folders conflux made on the way to the roots, recorded in the state root, which goes with
	// the roots: read first, whatever the check says of that root (paths.Dirs.Way), since all the
	// record can lead to is removing empty folders above the roots.
	way, wayErr := d.Way()

	// Its account goes with the installation's, and nothing may be running as it when it does:
	// the run ends itself, with its anchor, when it is stopped.
	if e, live := liveEphemeral(); live {
		ui.Errf("an ephemeral anchor is running from %s.\n"+
			"  Stop it first (Ctrl-C where it runs): uninstall removes the account it runs as", e.State)

		return ExitUsage
	}

	if !confirmUninstall(d, checked, *yes) {
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
		daemon.Reap(d, 35*time.Second)
	}

	// Each ephemeral run's root, but one inside the installation's -- a CONFLUX_DIR's -- which goes with
	// it, a killed run's anchord stopped first, where the root is this account's alone.
	for _, root := range paths.EphemeralCandidates() {
		if insideRoot(root, d) {
			switch found, err := removeKilledRun(root); {
			case err != nil:
				errs = append(errs, err)
			case found == liveRun:
				errs = append(errs, fmt.Errorf("an ephemeral run started from %s while conflux was being uninstalled", root))
			}

			continue
		}

		gone, err := removeEphemeralRoot(root)
		errs = append(errs, err)

		if gone {
			removed = append(removed, root)
		}
	}

	for _, dir := range outerRoots(d) {
		gone, err := paths.RemoveRoot(dir)
		errs = append(errs, err)

		if gone {
			removed = append(removed, dir)
		}
	}

	// Each of those folders that is empty now, deepest first.
	madeWay, err := paths.RemoveWay(way)
	removed = append(removed, madeWay...)
	errs = append(errs, err)

	// The service's log, where the platform keeps it in the system's own log directory, which is
	// not conflux's: the file and the one moved aside, and never the directory. Remove has taken it
	// already where a service was registered.
	if f := d.LogFile(); f != "" && !insideRoot(d.Log, d) {
		errs = append(errs, logfile.Remove(f))
	}

	if exe, err := updateExecutable(); err == nil {
		removed = append(removed, removeUpdateLeftovers(exe)...)
	}

	// The account anchord ran as, once nothing runs as it, if conflux made it.
	errs = append(errs, removeAccount())

	if err := errors.Join(errs...); err != nil {
		return fail(err)
	}

	if len(removed) > 0 {
		ui.Printf("Removed:\n")

		for _, r := range removed {
			ui.Printf("  %s\n", r)
		}

		ui.Println()
	}

	// A record that could not be read -- one that is a link, or behind a CONFLUX_DIR's way another
	// account may change -- leaves the folders it names, which are empty, and nothing else.
	if wayErr != nil {
		ui.Errf("the folders conflux made on the way to %s were left, since the record of them was not read: %v",
			d.State, wayErr)
	}

	ui.Printf("The boot service, the configuration, the identity and the state are gone, with everything else\n" +
		"conflux made. conflux up here again draws a new identity and a new overlay address.\n")

	return ExitOK
}

// outerRoots are d's roots that are conflux's and not inside another of them, each once: the ones
// uninstall removes, taking those inside with them -- run\ and logs\ on Windows and in a
// CONFLUX_DIR. The system's shared log directory, which macOS and FreeBSD keep the service's log
// in, is never one: it is inside no root, and it is not conflux's.
func outerRoots(d paths.Dirs) []string {
	var outer []string

	for _, dir := range []string{d.Config, d.State, d.Run} {
		if dir != "" && !insideRoot(dir, d) && !slices.Contains(outer, dir) {
			outer = append(outer, dir)
		}
	}

	return outer
}

// insideRoot reports whether dir sits strictly inside one of d's Config, State and Run.
func insideRoot(dir string, d paths.Dirs) bool {
	for _, other := range []string{d.Config, d.State, d.Run} {
		if other == "" || other == dir {
			continue
		}

		if rel, err := filepath.Rel(other, dir); err == nil && rel != "." && rel != ".." &&
			!strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return true
		}
	}

	return false
}

// removeEphemeralRoot removes the ephemeral root at root, where one is there, and says whether it
// did: a killed run's as removeKilledRun removes it, and one another account could have made or
// changed reading nothing in it, nor signalling anything it names (paths.RemoveRoot). A live run's,
// which uninstall has refused already, is one that started since.
func removeEphemeralRoot(root string) (bool, error) {
	switch found, err := removeKilledRun(root); {
	case err != nil:
		return found != noRun, err
	case found == liveRun:
		return false, fmt.Errorf("an ephemeral run started from %s while conflux was being uninstalled, "+
			"and it was left running.\n  Stop it (Ctrl-C where it runs), then run this again", root)
	case found == noRun:
		return false, nil
	}

	if _, err := paths.RemoveRoot(root); err != nil {
		return true, err
	}

	return true, nil
}

// runRoot is what removeKilledRun found at an ephemeral root.
type runRoot int

const (
	noRun      runRoot = iota // nothing there
	killedRun                 // a killed run's, removed
	liveRun                   // a live run's, its lock held, left as it is
	foreignRun                // one another account could have made or changed, left as it is
)

// removeKilledRun removes the ephemeral root at root where it is a killed run's -- this account's
// alone (paths.Foreign), its lock held by nobody -- stopping what that run left running from it
// first, under its lock, as a run's own clean-up does, so that one starting this moment is not
// emptied out from under itself; and says what it found. Nothing is read in one another account
// could have made or changed.
func removeKilledRun(root string) (runRoot, error) {
	switch err := foreignRoot(root); {
	case errors.Is(err, fs.ErrNotExist):
		return noRun, nil
	case err != nil:
		return foreignRun, nil
	}

	e := paths.EphemeralDirs(root)

	unlock, ok, err := flock.TryAcquire(e.ServeLockFile())

	switch {
	case err != nil:
		return killedRun, err
	case !ok:
		return liveRun, nil
	}

	return killedRun, daemon.RemoveEphemeral(e, unlock, nil)
}

// removeUpdateLeftovers removes what an update left beside exe, the conflux it replaced: a download
// that never went in place (update.Download's .conflux-update-*), and on Windows the image it moved
// aside (exe.old, which update.Replace makes there alone: elsewhere a file of that name is the
// operator's). Best effort: one still running is left -- on Windows the conflux an update ran from,
// which runs the new one's start or register, so its image goes at the next update, or uninstall.
// It returns what it removed.
func removeUpdateLeftovers(exe string) []string {
	var removed []string

	matches, _ := filepath.Glob(filepath.Join(filepath.Dir(exe), ".conflux-update-*"))

	if runtime.GOOS == "windows" {
		matches = append(matches, exe+".old")
	}

	for _, p := range matches {
		if err := os.Remove(p); err == nil {
			removed = append(removed, p)
		}
	}

	return removed
}

// confirmUninstall makes the irreversible part explicit before it happens. checked is what paths'
// check said of d's roots: where none is there there is nothing to destroy; where one failed, the
// identity in it is not read, and what is asked says why.
func confirmUninstall(d paths.Dirs, checked error, yes bool) bool {
	switch {
	case yes, errors.Is(checked, fs.ErrNotExist):
		return true
	case checked == nil && !config.HasManifest(d):
		return true
	}

	if !ui.IsTerminal() {
		ui.Errf("this deletes the credential and there is no other copy.\n" +
			"  Pass --yes to say so explicitly; a scripted uninstall will not destroy an identity by default.")

		return false
	}

	ui.Printf("\nThis deletes this machine's credential, and there is no other copy.\n\n")

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
