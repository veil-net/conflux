package paths

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
)

// allowsExec is MountAllowsExec, which a test stands a noexec filesystem in for.
var allowsExec = MountAllowsExec

// ErrNoExec is FirstExecutable's answer where every candidate is on a filesystem mounted
// noexec.
var ErrNoExec = errors.New("every candidate is on a filesystem mounted noexec")

// FirstExecutable is the first of candidates a program extracted beneath it may run from: one on a
// filesystem mounted to allow it, a candidate not there yet judged where it would be made
// (executable). Where none will do, it is ErrNoExec.
func FirstExecutable(candidates []string) (string, error) {
	for _, c := range candidates {
		ok, err := executable(c)
		if err != nil {
			return "", err
		}

		if ok {
			return c, nil
		}
	}

	return "", ErrNoExec
}

// executable reports whether a program extracted under root may run: whether the
// filesystem holding the nearest of root and its parents that exists is mounted to allow
// it, so a root not made yet is judged by where it would be made. It walks up by name and
// judges nothing: what it reads of a directory is the filesystem it is on, not who may
// change it; on Windows, which mounts nothing noexec, it reads nothing (MountAllowsExec).
func executable(root string) (bool, error) {
	for p := root; ; p = filepath.Dir(p) {
		ok, err := allowsExec(p)
		if !errors.Is(err, fs.ErrNotExist) || filepath.Dir(p) == p {
			if err != nil {
				return false, fmt.Errorf("read the filesystem holding %s: %w", root, err)
			}

			return ok, nil
		}
	}
}
