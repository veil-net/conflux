package daemon

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/libexec"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/service"
)

// anchorFiles are what anchor keeps in its -dir: the bootstrap cache, the realm links it
// adopted, the realm's knowledge (the blocks in force and the taint records, a Taints
// order's grant among them), and a list a member's Subnets order wrote. Nothing else there
// is anchor's to read. anchor's own temporaries (.<name>-<random>.tmp) are a write anchord
// did not finish, and no anchord runs while the directory is tidied.
var anchorFiles = named("bootstrap.json", "realmlinks", "knowledge", "subnets.json")

// rootNames are the root's own entries: what conflux keeps there, the directories in it, and
// what the platform's service manager or the service copy's last move left beside them. The
// same names in every root, so read once, off a root that is nowhere.
var rootNames = func() []string {
	d := paths.Dirs{}

	var out []string

	for _, p := range []string{
		d.ConfigFile(), d.StateFile(), d.ManifestFile(), d.DaemonConfigFile(), d.PrivilegeFile(),
		d.LockFile(), d.ServeLockFile(), d.ServiceExecutable(), d.Libexec(), d.AnchorDir(), d.RootAnchorDir(),
		d.RunDir(),
		// The copy a running Windows service's image was moved aside to, which the next Place
		// removes once nothing runs it.
		d.ServiceExecutable() + ".old",
		// FreeBSD's daemon(8)'s record of the supervisor, which rc.subr stops it by.
		d.RCPidFile(),
	} {
		out = append(out, filepath.Base(p))
	}

	return out
}()

// tidyRoot keeps the root's own entries to what conflux and anchor put there, removing
// everything else but a temporary file young enough to be another conflux's write in
// progress, and gives the root's own files back their owner and modes (restoreModes). Once a
// start, as Run puts the root back: only the supervisor's own account can write there, so
// nothing appears between one spawn and the next for it to take. The run directory a start
// empties whole, and the bin directory is libexec.Sweep's.
func (s *Supervisor) tidyRoot() error {
	return errors.Join(removeExcept(s.Dirs.Root, rootEntry), s.restoreModes())
}

// rootEntry keeps one of the root's own entries, or a write in progress.
func rootEntry(e fs.DirEntry) bool { return slices.Contains(rootNames, e.Name()) || inProgress(e) }

// tidyAnchorDirs removes from both anchor directories everything that is not anchor's. Before
// every spawn, once the account's leftovers are ended and before anything is laid out for the
// next anchord, so nothing it removes is in use: the account writes in its directory for as
// long as an anchord of its runs.
func (s *Supervisor) tidyAnchorDirs() error {
	return errors.Join(removeExcept(s.Dirs.AnchorDir(), anchorFiles), removeExcept(s.Dirs.RootAnchorDir(), anchorFiles))
}

// removeExcept removes every entry of dir that keep does not keep, going on past one that will
// not go, and returns every failure. dir is opened as a root, so an entry somebody made in it --
// a link above all, in an anchor directory, which anchord's account can write -- leads the
// removal nowhere outside it. A dir that is not there holds nothing to remove.
func removeExcept(dir string, keep func(fs.DirEntry) bool) error {
	r, err := os.OpenRoot(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}

	if err != nil {
		return err
	}
	defer r.Close()

	entries, err := fs.ReadDir(r.FS(), ".")
	if err != nil {
		return err
	}

	var errs []error

	for _, e := range entries {
		if keep(e) {
			continue
		}

		if err := r.RemoveAll(e.Name()); err != nil {
			errs = append(errs, fmt.Errorf("remove %s: %w", filepath.Join(dir, e.Name()), err))
		}
	}

	return errors.Join(errs...)
}

// named keeps the entries called one of names.
func named(names ...string) func(fs.DirEntry) bool {
	return func(e fs.DirEntry) bool { return slices.Contains(names, e.Name()) }
}

// nothing keeps no entry.
func nothing(fs.DirEntry) bool { return false }

// inProgress reports whether e is a temporary file another conflux may still be writing: an
// atomic write's (config.TempPrefix), or the service copy's (service.StagedPrefix), younger
// than one a crash left would be.
func inProgress(e fs.DirEntry) bool {
	if !strings.HasPrefix(e.Name(), config.TempPrefix) && !strings.HasPrefix(e.Name(), service.StagedPrefix) {
		return false
	}

	info, err := e.Info()

	return err == nil && time.Since(info.ModTime()) < libexec.TransientAge
}
