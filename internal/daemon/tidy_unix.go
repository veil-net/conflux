//go:build !windows

package daemon

import (
	"errors"
	"io/fs"
	"os"
)

// restoreModes gives the root's own files back to the supervisor, at 0600, and the copy of
// conflux the service runs at 0700, whatever they were changed to since: what holds the
// identity, the configuration or a lock is nobody else's to read. Only regular files: the
// root is root's alone, and what is not a file here is not conflux's.
func (s *Supervisor) restoreModes() error {
	d := s.Dirs
	uid, gid := os.Geteuid(), os.Getegid()

	var errs []error

	for path, mode := range map[string]fs.FileMode{
		d.ConfigFile(): 0o600, d.StateFile(): 0o600, d.ManifestFile(): 0o600, d.PrivilegeFile(): 0o600,
		d.LockFile(): 0o600, d.ServeLockFile(): 0o600, d.ServiceExecutable(): 0o700,
	} {
		if fi, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() {
			continue
		}

		errs = append(errs, ownAs(path, uid, gid, mode))
	}

	return errors.Join(errs...)
}
