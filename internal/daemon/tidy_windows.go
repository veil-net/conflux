package daemon

import (
	"errors"
	"os"

	"github.com/veil-net/conflux/internal/paths"
)

// restoreModes gives the root's own files (rootFiles) back to SYSTEM and the Administrators,
// as Unix gives them back their modes: each that another account owns, or whose DACL grants
// anybody else, is restricted again (paths.Restrict). The root's DACL is no help here: a file's
// own DACL keeps a grant somebody added to it beside whatever it inherits, and what conflux
// writes atomically has a protected DACL of its own, which inherits nothing. Only regular
// files, as on Unix.
func (s *Supervisor) restoreModes() error {
	var errs []error

	for _, f := range rootFiles(s.Dirs) {
		if fi, err := os.Lstat(f.path); err != nil || !fi.Mode().IsRegular() || paths.OnlyAdmins(f.path) {
			continue
		}

		errs = append(errs, paths.Restrict(f.path, false))
	}

	return errors.Join(errs...)
}
