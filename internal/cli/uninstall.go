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

	// The roots uninstall refuses (JudgeWays): a CONFLUX_DIR whose way another account may change, the
	// CONFLUX_DIR included, held to parents' rule as the readers' check holds it, since whoever could
	// change it could have put anything at the root's name, and could lead the removal elsewhere.
	// Judged for every root before anything is asked or removed, so nothing is half-removed; paths'
	// advice, which is for choosing a CONFLUX_DIR, gives way to uninstall's. Any other failure to walk
	// the way to a root stops uninstall there too, before it acts.
	if err := judgeWays(d); err != nil {
		what, _, _ := strings.Cut(err.Error(), "\n")

		if errors.Is(err, paths.ErrWayRefused) {
			ui.Errf("%s\n  So conflux cannot know that what is there is its own, and uninstall removed nothing, the "+
				"boot service included.\n  Once nobody else can change any folder on the way to it, run conflux "+
				"uninstall again", what)
		} else {
			ui.Errf("%s\n  uninstall stopped there, before it acted: nothing was removed, the boot service included.",
				what)
		}

		return ExitError
	}

	// What uninstall reads or signals by a name in a root -- the identity it asks about, the pid
	// record it stops anchord by -- it reads only where the root passes paths' check, as conflux makes
	// a root. A root that fails is removed all the same, reading nothing (paths.RemoveRoot), as itself
	// where it is a link.
	checked := d.Check()

	// The folders conflux made on the way to the roots, recorded in the state root, which goes with
	// the roots: read first (paths.Dirs.Way); all the record can lead to is removing empty folders
	// above the roots.
	way, wayErr := d.Way()

	// An ephemeral run's account goes with the installation's, and nothing may be running as it when it
	// does, nor from a root that goes, as one inside a CONFLUX_DIR would: the run ends itself, with its
	// anchor, when it is stopped. Asked before anything is asked, and again once it is answered, before
	// anything is removed.
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

	// Each ephemeral run's root, a killed run's anchord stopped first, where the root is as conflux makes
	// one: one inside the installation's -- a CONFLUX_DIR's -- is emptied, and goes with it, and where
	// the installation's root failed the readers' check goes with it unread. A run that started since
	// uninstall asked is left running: its root, the installation's roots where it is inside them, and
	// its account.
	var (
		started       []string
		startedInside bool
	)

	for _, root := range ephemeralCandidates() {
		if d.Inside(root) {
			if checked != nil {
				continue
			}

			switch found, err := removeKilledRun(root); {
			case err != nil:
				errs = append(errs, err)
			case found == liveRun:
				started, startedInside = append(started, root), true
			}

			continue
		}

		gone, err := removeEphemeralRoot(root)
		if errors.Is(err, errStarted) {
			started = append(started, root)

			continue
		}

		errs = append(errs, err)

		if gone {
			removed = append(removed, root)
		}
	}

	for _, root := range started {
		errs = append(errs, fmt.Errorf("an ephemeral run started from %s while conflux was being uninstalled, and "+
			"it was left running, with what it runs from.\n  Stop it (Ctrl-C where it runs), then run this again",
			root))
	}

	for _, dir := range d.Outer() {
		if startedInside {
			break
		}

		gone, err := removeRoot(dir)
		errs = append(errs, err)

		if gone && err == nil {
			removed = append(removed, dir)
		}
	}

	// Each of those folders that is empty now, deepest first.
	madeWay, err := paths.RemoveWay(way)
	removed = append(removed, madeWay...)
	errs = append(errs, err)

	// Remove has taken the service's log already where a service was registered.
	errs = append(errs, removeSharedLog(d))

	if exe, err := updateExecutable(); err == nil {
		removed = append(removed, removeUpdateLeftovers(exe)...)
	}

	// The accounts anchord ran as, if conflux made them, stopping whatever runs as each: the ephemeral
	// runs' unless one started since.
	errs = append(errs, removeAccounts(len(started) == 0))

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

// reap is daemon.Reap, which a test counts.
var reap = daemon.Reap

// confirm is confirmUninstall, which a test answers, starting an ephemeral run as it is asked.
var confirm = confirmUninstall

// removeAccounts is removeAccount, which a test records.
var removeAccounts = removeAccount

// judgeWays is paths.Dirs.JudgeWays, which a test has refuse a root as the top a SUBST letter gives a
// folder, which only Windows has.
var judgeWays = paths.Dirs.JudgeWays

// removeRoot is paths.RemoveRoot, which a test has fail with something at the root's name.
var removeRoot = paths.RemoveRoot

// ephemeralCandidates is paths.EphemeralCandidates, which a test points at roots outside the
// installation's: under a CONFLUX_DIR every candidate is inside it.
var ephemeralCandidates = paths.EphemeralCandidates

// removeSharedLog removes the service's log where the platform keeps it in the system's own log
// directory, outside d's roots, which is not conflux's: the file and the one moved aside, and never the
// directory. One in a root goes with it.
func removeSharedLog(d paths.Dirs) error {
	if f := d.LogFile(); f != "" && !d.Inside(d.Log) {
		return logfile.Remove(f)
	}

	return nil
}

// liveRefused refuses uninstall while an ephemeral run is live, naming its root, and says whether it
// did.
func liveRefused() bool {
	e, live := liveEphemeral()
	if live {
		ui.Errf("an ephemeral anchor is running from %s.\n"+
			"  Stop it first (Ctrl-C where it runs): uninstall removes the account it runs as, and the root "+
			"it runs from", e.State)
	}

	return live
}

// removeEphemeralRoot removes the ephemeral root at root, where one is there, and says whether it is
// gone, which one it failed to empty is not: a killed run's as removeKilledRun removes it, under its
// lock, and nothing after, so a run that takes it the moment the lock is let go of keeps it, and it is
// not gone. A live run's, which uninstall has refused already, is one that started since, and is
// errStarted.
func removeEphemeralRoot(root string) (bool, error) {
	switch found, err := removeKilledRun(root); {
	case err != nil:
		return false, err
	case found == liveRun:
		return false, errStarted
	case found == noRun:
		return false, nil
	}

	_, err := os.Lstat(root)

	return errors.Is(err, fs.ErrNotExist), nil
}

// errStarted is an ephemeral run that started since uninstall asked whether one was live.
var errStarted = errors.New("an ephemeral run started")

// runRoot is what removeKilledRun found at an ephemeral root.
type runRoot int

const (
	noRun     runRoot = iota // nothing there
	killedRun                // a killed run's, or one not as conflux makes a root, removed
	liveRun                  // a live run's, its lock held, left as it is
)

// removeKilledRun removes the ephemeral root at root where it is a killed run's -- as conflux makes a
// root (foreignRoot), its lock held by nobody -- stopping what that run left running from it first,
// under its lock, as a run's own clean-up does, so that one starting this moment is not emptied out from
// under itself (daemon.RemoveEphemeral); and says what it found. What is at the root's name and is not
// as conflux makes a root is nothing of a run's: it is removed as itself (paths.RemoveRoot), and nothing
// in it read or signalled.
func removeKilledRun(root string) (runRoot, error) {
	switch err := foreignRoot(root); {
	case errors.Is(err, fs.ErrNotExist):
		return noRun, nil
	case err != nil:
		_, err := removeRoot(root)

		return killedRun, err
	}

	e := paths.EphemeralDirs(root)

	unlock, ok, err := flock.TryAcquire(e.ServeLockFile())

	switch {
	case err != nil:
		return killedRun, err
	case !ok:
		return liveRun, nil
	}

	return killedRun, removeEphemeral(e, unlock, nil)
}

// removeEphemeral is daemon.RemoveEphemeral, which a test points at one that lets a run take the root
// as it lets go of the root's lock.
var removeEphemeral = daemon.RemoveEphemeral

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
// identity in it is not read, and what is asked says why. It asks where an identity is there, or may
// be, and wherever d is a CONFLUX_DIR's -- whose root, inside a folder whoever set the variable chose,
// uninstall removes whether an identity is in it or not; off a terminal, without yes, it refuses, so a
// scripted uninstall destroys neither by default.
func confirmUninstall(d paths.Dirs, checked error, yes bool) bool {
	if yes || errors.Is(checked, fs.ErrNotExist) {
		return true
	}

	root := paths.Root()
	identity := checked != nil || config.HasManifest(d)

	var stakes string

	switch {
	case root == "" && !identity:
		return true
	case root == "":
		stakes = "deletes this machine's credential, and there is no other copy"
	case identity:
		stakes = "removes " + d.State + " and everything in it, this machine's credential among it, and there is no " +
			"other copy of that"
	default:
		stakes = "removes " + d.State + " and everything in it"
	}

	if !ui.IsTerminal() {
		ui.Errf("this %s.\n  Pass --yes to say so explicitly; a scripted uninstall destroys nothing by default.", stakes)

		return false
	}

	ui.Printf("\nThis %s.\n\n", stakes)

	if !identity {
		return ui.Confirm("Continue?")
	}

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
