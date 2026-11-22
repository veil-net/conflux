package paths

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

// An ephemeral run keeps nothing of the machine's: no configuration, no identity, no
// state, no boot service. What it needs while it runs -- the lock that makes it the only
// one, the bearer token and the socket, the record of the anchord it started, and the
// extracted pair it runs -- goes in a root of its own, and the root is removed when the run
// ends. Fixed rather than drawn per run, so that a second run is refused by the lock, the
// next run can stop an anchord a killed one left, and `conflux status` from another
// terminal can find the socket.

// ephemeralName is the root's name in an ordinary user's own directories.
const ephemeralName = "conflux-ephemeral"

// EphemeralDirs are the four roots of an ephemeral run kept in root: Config and State the
// root itself, though nothing is ever written as either, Run beneath it, and no log
// directory, since an ephemeral run's output goes to the terminal it runs in. They are an
// ephemeral run's, which no service serves.
func EphemeralDirs(root string) Dirs {
	return Dirs{Config: root, State: root, Run: filepath.Join(root, runName), ephemeral: true}
}

// EphemeralCandidates are where an ephemeral run may be kept, in the order one is chosen.
//
// Per identity, because the user running conflux decides what it may write: root's, and an elevated
// administrator's on Windows, inside the installation's root, DirName, as under a CONFLUX_DIR, which
// every run keeps it in; anybody else's under their own runtime directory, a filesystem in memory where
// the platform has one, and then their cache directory, for a host that mounts the first noexec. Both
// are looked in for a run that is live.
func EphemeralCandidates() []string {
	if Root() != "" || runtime.GOOS == "windows" || os.Geteuid() == 0 {
		return []string{filepath.Join(Default().State, "ephemeral")}
	}

	var roots []string

	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" && filepath.IsAbs(xdg) {
		roots = append(roots, filepath.Join(xdg, ephemeralName))
	} else {
		roots = append(roots, filepath.Join(os.TempDir(), ephemeralName+"-"+strconv.Itoa(os.Geteuid())))
	}

	if cache, err := os.UserCacheDir(); err == nil {
		roots = append(roots, filepath.Join(cache, ephemeralName))
	}

	return roots
}

// Ephemeral is the root a new ephemeral run is kept in: the first candidate on a filesystem that lets
// the extracted anchord run, and either not there yet or as conflux makes a root (Check), or made so
// afresh: what is at a candidate's name and is not as conflux makes a root is removed as itself and the
// root made there (EnsureAll), once the folder it is in is found on such a filesystem, and only a
// candidate that cannot be is passed over, what is at its name left as it was. tmpfs is often mounted
// noexec, and anchord extracted there would be refused at exec with a reason that names nothing; and
// /tmp lets anybody make the name a run's root would have, which only its owner can remove.
func Ephemeral() (Dirs, error) { return ephemeralIn(EphemeralCandidates()) }

// ephemeralIn is Ephemeral among candidates.
func ephemeralIn(candidates []string) (Dirs, error) {
	root, err := FirstExecutable(candidates, func(c string) error {
		e := EphemeralDirs(c)

		if err := e.Check(); err == nil || errors.Is(err, fs.ErrNotExist) {
			return err
		}

		switch ok, err := executable(filepath.Dir(c)); {
		case err != nil:
			return err
		case !ok:
			return fmt.Errorf("%s is on a filesystem mounted noexec: %w", c, ErrNoExec)
		}

		return e.EnsureAll()
	})
	if errors.Is(err, ErrNoExec) {
		return Dirs{}, fmt.Errorf("every place an ephemeral run is kept is on a filesystem mounted noexec, "+
			"so the anchord it extracts could not run: %v.\n  Set CONFLUX_DIR to a directory on one that is not", candidates)
	}

	if err != nil {
		return Dirs{}, err
	}

	return EphemeralDirs(root), nil
}

// allowsExec is MountAllowsExec, which a test stands a noexec filesystem in for.
var allowsExec = MountAllowsExec

// ErrNoExec is FirstExecutable's answer where every candidate is on a filesystem mounted
// noexec.
var ErrNoExec = errors.New("every candidate is on a filesystem mounted noexec")

// FirstExecutable is the first of candidates a program extracted beneath it may run from:
// one on a filesystem mounted to allow it, and not one refuse turns down, where refuse is
// given. A candidate refuse finds not there (fs.ErrNotExist) is taken as one to make, and its
// filesystem read where it would be made, in the directory above it: nothing at its name is read
// once refuse has looked. One refuse turns down for its filesystem alone (ErrNoExec) is passed over
// as a noexec one is. Where none will do, the first other refusal is the error, or else ErrNoExec.
func FirstExecutable(candidates []string, refuse func(string) error) (string, error) {
	var refused error

	for _, c := range candidates {
		at := c

		if refuse != nil {
			switch err := refuse(c); {
			case errors.Is(err, fs.ErrNotExist):
				at = filepath.Dir(c)
			case errors.Is(err, ErrNoExec):
				continue
			case err != nil:
				if refused == nil {
					refused = err
				}

				continue
			}
		}

		ok, err := executable(at)
		if err != nil {
			return "", err
		}

		if ok {
			return c, nil
		}
	}

	if refused != nil {
		return "", refused
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
