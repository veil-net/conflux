package cli

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/flock"
	"github.com/veil-net/conflux/internal/libexec"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/service"
	"github.com/veil-net/conflux/internal/ui"
)

// tidy removes what earlier conflux left in every place conflux keeps files, before the service starts
// on this conflux, in place of EnsureAll, which it runs itself: `register`, which update has the conflux
// it put in place run, calls it always; and up, proxy, observe, install, enrol and start call it
// (handOver) where staleCopy finds what earlier conflux left -- the service's copy not there, not as
// conflux makes it, or not this conflux, as after an update or a newer conflux put in place by hand or
// by an install script, or the roots refused by paths' check for anything but not being there. Nothing
// of the machine's is touched -- the configuration, the identity, the state and the log stay -- and what
// is removed is made again, fresh, by this conflux.
//
//   - The service is stopped where a supervisor serves the root, asked of its serve lock through the
//     root held (flock.HeldIn): a way to a CONFLUX_DIR that another account may change is refused
//     there, before anything is stopped. A root paths' check refuses for anything but not being there
//     -- checked, what the caller's check of d said -- holds no lock conflux reads, and a supervisor may
//     serve it all the same, so the service is stopped there too, before EnsureAll makes the root
//     afresh. A supervisor the boot service did not start -- one run by hand -- is refused too, with
//     nothing removed (stopServing). stopped says the service was stopped, for the caller to start it
//     again, on this conflux, however it ends (startAgain).
//   - The roots are made as conflux makes them (EnsureAll), and the serve lock held from then on, so
//     no supervisor starts while tidy works.
//   - The anchord a dead supervisor left is stopped (daemon.ReapOrphan), and the run directory
//     emptied: the token, the readiness marker, the pid record, anchord's socket directory, which
//     the next supervisor makes again.
//   - The bin directory is emptied -- every set, this build's among them, and what a crashed
//     extraction left staged -- and this build's pair extracted afresh (libexec.Remake), an extraction
//     in progress waited for until ctx ends: where it cannot be, tidy fails once it has done the rest,
//     since a set planted there would be kept.
//   - A killed ephemeral run's root is removed, the anchord it left stopped (removeKilledRun); a
//     live run's is left.
//   - Where nothing holds the state's lock, what an atomic write that never went in place left in the
//     configuration and state directories goes (removeStaged). The lock files themselves are kept on
//     Unix, and on Windows removed once let go of, for whatever next takes them to make again
//     (flock.Drop).
//   - What an update left beside the conflux it replaced goes, and so do the temporary copies of
//     anchorctl readers killed before they removed them left (removeLeftovers).
//
// The service's copy is the caller's to write afresh (service.PlaceAfresh), with what a copy that
// never went in place left beside it. What the next start clears again as it starts -- the orphan,
// the run directory, a killed run's root -- it warns of where it cannot remove it, and goes on
// (leftBehind); and what is gone, and nothing else, it lists, however far it got.
func tidy(ctx context.Context, d paths.Dirs, mgr service.Manager, checked error) (stopped bool, err error) {
	var removed []string

	defer func() { listRemoved(removed) }()

	served, err := flock.HeldIn(d, d.ServeLockFile())
	if err != nil {
		return false, err
	}

	if !served {
		served = checked != nil && !errors.Is(checked, fs.ErrNotExist)
	}

	if served {
		if stopped, err = stopServing(d, mgr); err != nil {
			return stopped, err
		}
	}

	if err := ensureAll(d); err != nil {
		return stopped, err
	}

	// One that took the root since is no service tidy stopped either, and nothing is started beside it.
	unlock, ok, err := flock.TryAcquire(d.ServeLockFile())

	switch {
	case err != nil:
		return stopped, err
	case !ok:
		return false, fmt.Errorf("a conflux supervisor started serving %s as what earlier conflux left there was "+
			"being removed, so the rest cannot be, and nothing was started.\n  Stop it, then run this again", d.State)
	}

	_, err = daemon.ReapOrphan(d)
	leftBehind(err)

	cleared, err := paths.ClearExcept(d.Run)
	leftBehind(err)
	removed = append(removed, cleared...)

	// Every set but the one Remake extracts again, and what was staged.
	set := filepath.Join(d.Libexec(), anchor.SetID())
	emptied, remakeErr := libexec.Remake(ctx, d)
	removed = append(removed, slices.DeleteFunc(emptied, func(p string) bool { return p == set })...)

	for _, root := range paths.EphemeralCandidates() {
		found, err := removeKilledRun(root)
		leftBehind(err)

		if _, err := os.Lstat(root); found == killedRun && errors.Is(err, fs.ErrNotExist) {
			removed = append(removed, root)
		}
	}

	removed = append(removed, removeStaged(d)...)

	unlock()

	if flock.Drop(d.ServeLockFile()) {
		removed = append(removed, d.ServeLockFile())
	}

	removed = append(removed, removeLeftovers()...)

	return stopped, remakeErr
}

// ensureAll is paths.Dirs.EnsureAll, after which a test has a supervisor take the root.
var ensureAll = paths.Dirs.EnsureAll

// stopServing stops the boot service, for a root a supervisor serves, and says whether it stopped it:
// where the service manager says it runs, Stop. Then the serve lock is asked after again: still held,
// its holder is a supervisor the boot service did not start -- one run by hand -- which is refused,
// naming it, before anything is removed; and nothing is started again, since the service, started,
// would find that supervisor there and exit. Where the service manager cannot say, which supervisor
// that is cannot be told, and it is refused saying so, with nothing stopped.
func stopServing(d paths.Dirs, mgr service.Manager) (bool, error) {
	running, err := mgr.Running()
	if err != nil {
		return false, fmt.Errorf("a conflux supervisor serves %s, and the service manager could not say whether it "+
			"is the boot service: %w.\n  Nothing was stopped, removed or started; run this again once it answers",
			d.State, err)
	}

	if running {
		if err := mgr.Stop(); err != nil {
			return false, err
		}
	}

	switch held, err := flock.HeldIn(d, d.ServeLockFile()); {
	case err != nil:
		return running, err
	case held:
		return false, fmt.Errorf("a conflux supervisor the boot service did not start -- one run by hand -- serves "+
			"%s, so what earlier conflux left there cannot be removed, and nothing was started.\n  Stop it, then "+
			"run this again", d.State)
	}

	return running, nil
}

// leftBehind warns of err, what tidy could not remove of what the next supervisor or ephemeral run
// clears again as it starts -- an anchord a dead supervisor left, the run directory, a killed run's
// root -- which it goes on without.
func leftBehind(err error) {
	if err != nil {
		ui.Errf("what earlier conflux left was not all removed, and the next start clears the rest: %v", err)
	}
}

// listRemoved says what tidy removed, where it removed anything.
func listRemoved(removed []string) {
	if len(removed) == 0 {
		return
	}

	ui.Printf("Removed what earlier conflux left:\n")

	for _, r := range removed {
		ui.Printf("  %s\n", r)
	}

	ui.Println()
}

// removeStaged removes, where nothing holds the state's lock, what an atomic write that never went
// in place left in the configuration and state directories (paths.WriteAtomic's .tmp- files), and
// then, once it has let go of it, the lock file itself where flock.Drop does. Every writer of the
// manifest and the state holds that lock, and nothing else writes there with the service stopped and
// its supervisor's lock held, so none is mid-write. A lock held is in use, and kept with what it
// guards. It returns what it removed.
func removeStaged(d paths.Dirs) []string {
	lock := d.LockFile()
	if _, err := os.Lstat(lock); err != nil {
		return nil
	}

	unlock, ok, err := flock.TryAcquire(lock)
	if err != nil || !ok {
		return nil
	}

	var removed []string

	for _, dir := range slices.Compact([]string{d.Config, d.State}) {
		removed = append(removed, paths.RemovePrefixed(dir, ".tmp-", os.Remove)...)
	}

	unlock()

	if flock.Drop(lock) {
		removed = append(removed, lock)
	}

	return removed
}
