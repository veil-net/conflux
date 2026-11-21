package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"

	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/flock"
	"github.com/veil-net/conflux/internal/libexec"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/service"
	"github.com/veil-net/conflux/internal/ui"
)

// tidy removes what earlier conflux left in every place conflux keeps files, for the conflux an
// update has just put in place, before anything judges its roots and before its service starts:
// update hands the service over through this conflux's `register` or `start`, and those call it in
// place of EnsureAll, which it runs itself once what would fail it is gone. Nothing of the machine's
// is touched -- the configuration, the identity, the state and the log stay -- and what is removed is
// made again, fresh, by this conflux.
//
//   - The service is stopped where a supervisor serves the root, asked of its serve lock without
//     trusting the root (flock.Held), since nothing has judged it yet; stopped says it was, for a
//     caller that starts nothing to start it again on this conflux.
//   - What conflux makes again by its name in an installation's root and finds failing the rule the
//     SYSTEM service holds it to -- an older conflux's on a Windows client, the administrator's own --
//     is removed through handles (paths' RemakeOld), and anything else failing it refused; then the
//     roots are secured (EnsureAll), and the serve lock held from then on, so no supervisor starts
//     while tidy works.
//   - The anchord a dead supervisor left is stopped (daemon.ReapOrphan), and the run directory
//     emptied: the token, the readiness marker, the pid record, anchord's socket directory, which
//     the next supervisor makes again.
//   - The bin directory is emptied -- every set, this build's among them, and what a crashed
//     extraction left staged -- and this build's pair extracted afresh (libexec.Remake).
//   - A killed ephemeral run's root is removed, the anchord it left stopped (removeKilledRun); a
//     live run's, and one another account could have made, are left.
//   - Where nothing holds the state's lock, what an atomic write that never went in place left in the
//     configuration and state directories goes (removeStaged). The lock files themselves are kept on
//     Unix, and on Windows removed once let go of, for whatever next takes them to make again
//     (dropLock).
//   - What an update left beside the conflux it replaced goes (removeUpdateLeftovers).
//
// The service's copy is the caller's to write afresh (service.PlaceAfresh), with what a copy that
// never went in place left beside it. What it removed it lists, however far it got.
func tidy(d paths.Dirs, mgr service.Manager) (stopped bool, err error) {
	var removed []string

	defer func() { listRemoved(removed) }()

	switch held, err := flock.Held(d.ServeLockFile()); {
	case err != nil:
		return false, err
	case held:
		if err := mgr.Stop(); err != nil {
			return false, err
		}

		stopped = true
	}

	remade, err := d.RemakeOld()
	if removed = remade; err != nil {
		return stopped, err
	}

	if err := d.EnsureAll(); err != nil {
		return stopped, err
	}

	unlock, ok, err := flock.TryAcquire(d.ServeLockFile())

	switch {
	case err != nil:
		return stopped, err
	case !ok:
		return stopped, fmt.Errorf("a conflux supervisor still serves %s with the boot service stopped, so what "+
			"earlier conflux left there cannot be removed.\n  Stop it, then run this again", d.State)
	}

	_, err = daemon.ReapOrphan(d)
	errs := []error{err}

	removed = append(removed, entries(d.Run, "")...)
	_, err = paths.ClearExcept(d.Run, "")
	errs = append(errs, err)

	// Every set but the one Remake extracts again, and what was staged.
	set := filepath.Join(d.Libexec(), anchor.SetID())
	removed = append(removed, entries(d.Libexec(), set, filepath.Join(d.Libexec(), ".lock"))...)

	if _, err := libexec.Remake(d); err != nil {
		errs = append(errs, err)
	}

	for _, root := range paths.EphemeralCandidates() {
		switch found, err := removeKilledRun(root); {
		case err != nil:
			errs = append(errs, err)
		case found == killedRun:
			removed = append(removed, root)
		}
	}

	removed = append(removed, removeStaged(d)...)

	unlock()

	if dropLock(d.ServeLockFile()) {
		removed = append(removed, d.ServeLockFile())
	}

	if exe, err := updateExecutable(); err == nil {
		removed = append(removed, removeUpdateLeftovers(exe)...)
	}

	return stopped, errors.Join(errs...)
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

// entries are the paths of what dir holds but skip; none where it is not there.
func entries(dir string, skip ...string) []string {
	list, _ := os.ReadDir(dir)

	var found []string

	for _, e := range list {
		if p := filepath.Join(dir, e.Name()); !slices.Contains(skip, p) {
			found = append(found, p)
		}
	}

	return found
}

// removeStaged removes, where nothing holds the state's lock, what an atomic write that never went
// in place left in the configuration and state directories (config's .tmp- files), and then, once it
// has let go of it, the lock file itself where dropLock does. Every writer of the manifest and the
// state holds that lock, and nothing else writes there with the service stopped and its supervisor's
// lock held, so none is mid-write. A lock held is in use, and kept with what it guards. It returns
// what it removed.
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
		staged, _ := filepath.Glob(filepath.Join(dir, ".tmp-*"))
		for _, p := range staged {
			if os.Remove(p) == nil {
				removed = append(removed, p)
			}
		}
	}

	unlock()

	if dropLock(lock) {
		removed = append(removed, lock)
	}

	return removed
}

// dropLock removes the lock file at path, which nothing holds now, where the system removes no file
// anybody has open (Windows), so whatever takes it next makes it again; and says whether it did. On
// Unix it is kept: a lock is taken on the file its name led to when it was opened, so one waited for
// on a file removed meanwhile would be held beside one taken on the file made again at its name.
func dropLock(path string) bool {
	return runtime.GOOS == "windows" && os.Remove(path) == nil
}
