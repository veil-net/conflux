package daemon

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// anchorFiles are what anchor keeps in its -dir: the bootstrap cache, the realm links it
// adopted, the realm's knowledge (the blocks in force and the taint records, a Taints
// order's grant among them), and a list a member's Subnets order wrote. Nothing else there
// is anchor's to read. anchor's own temporaries (.<name>-<random>.tmp) are a write anchord
// did not finish, and no anchord runs while the directory is tidied.
var anchorFiles = []string{"bootstrap.json", "realmlinks", "knowledge", "subnets.json"}

// transientAge is how long a temporary file in the root may be another conflux's write in
// progress -- an atomic write's (.tmp-*), or the service copy's (.conflux-*) -- rather than
// one a crash left.
const transientAge = time.Hour

// tidy keeps the root to what conflux and anchor put there, and removes everything else: the
// root's own entries, its run directory's, and both anchor directories'. The bin directory is
// libexec.Sweep's. Run before every spawn, once the account's leftovers are ended and before
// anything is laid out for the next anchord, so nothing it removes is in use.
//
// Each anchor directory is opened as a root, so an entry the account made in its own
// directory -- a link above all -- leads the removal nowhere outside it.
func (s *Supervisor) tidy() error {
	d := s.Dirs

	root := names(d.ConfigFile(), d.StateFile(), d.ManifestFile(), d.DaemonConfigFile(), d.PrivilegeFile(),
		d.LockFile(), d.ServeLockFile(), d.ServiceExecutable(), d.Libexec(), d.AnchorDir(), d.RootAnchorDir(),
		d.RunDir(),
		// The copy a running Windows service's image was moved aside to, which the next Place
		// removes once nothing runs it.
		d.ServiceExecutable()+".old")

	if l := d.LogFile(); l != "" {
		root = append(root, filepath.Base(l), filepath.Base(l)+".1")
	}

	run := names(d.TokenFile(), d.DaemonPIDFile(), d.ReadyFile(), d.DaemonRun())

	errs := []error{
		removeUnknown(d.Root, root, true),
		removeUnknown(d.RunDir(), run, false),
	}

	for _, dir := range []string{d.AnchorDir(), d.RootAnchorDir()} {
		errs = append(errs, keepAnchorFiles(dir))
	}

	return errors.Join(errs...)
}

// names are the base names of paths.
func names(paths ...string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = filepath.Base(p)
	}

	return out
}

// removeUnknown removes every entry of dir not named in known, sparing, where transient is
// set, a temporary file young enough to be a write in progress.
func removeUnknown(dir string, known []string, transient bool) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}

	if err != nil {
		return err
	}

	var errs []error

	for _, e := range entries {
		name := e.Name()
		if slices.Contains(known, name) || (transient && inProgress(e)) {
			continue
		}

		errs = append(errs, os.RemoveAll(filepath.Join(dir, name)))
	}

	return errors.Join(errs...)
}

// inProgress reports whether e is a temporary file another conflux may still be writing.
func inProgress(e fs.DirEntry) bool {
	if !strings.HasPrefix(e.Name(), ".tmp-") && !strings.HasPrefix(e.Name(), ".conflux-") {
		return false
	}

	info, err := e.Info()

	return err == nil && time.Since(info.ModTime()) < transientAge
}

// keepAnchorFiles removes from the anchor directory dir everything that is not anchor's.
func keepAnchorFiles(dir string) error {
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
		if !slices.Contains(anchorFiles, e.Name()) {
			errs = append(errs, r.RemoveAll(e.Name()))
		}
	}

	return errors.Join(errs...)
}
