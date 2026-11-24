//go:build !windows

package daemon

import (
	"errors"
	"os"
)

// restoreModes gives the root's own files (rootFiles) back to the supervisor, at their modes --
// 0600, and 0700 for the copy of conflux the service runs -- whatever they were changed to
// since. Only regular files: the root is root's alone, and what is not a file here is not
// conflux's.
func (s *Supervisor) restoreModes() error {
	uid, gid := os.Geteuid(), os.Getegid()

	var errs []error

	for _, f := range rootFiles(s.Dirs) {
		if fi, err := os.Lstat(f.path); err != nil || !fi.Mode().IsRegular() {
			continue
		}

		if _, err := ownAs(f.path, uid, gid, f.mode); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}
