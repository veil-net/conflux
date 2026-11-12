package paths

import (
	"errors"
	"fmt"
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

// ephemeralName is the root's name, beside the machine's own directories.
const ephemeralName = "conflux-ephemeral"

// EphemeralDirs are the four roots of an ephemeral run kept in root: Config and State the
// root itself, though nothing is ever written as either, Run beneath it, and no log
// directory, since an ephemeral run's output goes to the terminal it runs in.
func EphemeralDirs(root string) Dirs {
	return Dirs{Config: root, State: root, Run: filepath.Join(root, "run")}
}

// EphemeralCandidates are where an ephemeral run may be kept, in the order one is chosen:
// a filesystem in memory where the platform has one, and then one on disk, for a host that
// mounts the first noexec. Both are looked in for a run that is live.
//
// Per identity, because the user running conflux decides what it may write: root's under
// the system's run directory, anybody else's under their own. Under CONFLUX_DIR, inside it
// and nowhere else.
func EphemeralCandidates() []string {
	if root := Root(); root != "" {
		return []string{filepath.Join(root, "ephemeral")}
	}

	if runtime.GOOS == "windows" {
		return []string{filepath.Join(filepath.Dir(platformDirs().State), ephemeralName)}
	}

	if os.Geteuid() == 0 {
		return []string{
			filepath.Join(ephemeralRunBase(), ephemeralName),
			platformDirs().State + "-ephemeral",
		}
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

// ephemeralRunBase is the system's directory of runtime files, which a reboot empties.
func ephemeralRunBase() string {
	if runtime.GOOS == "linux" {
		return "/run"
	}

	return "/var/run"
}

// Ephemeral is the root a new ephemeral run is kept in: the first candidate on a
// filesystem that lets the extracted anchord run. tmpfs is often mounted noexec, and
// anchord extracted there would be refused at exec with a reason that names nothing.
func Ephemeral() (Dirs, error) {
	candidates := EphemeralCandidates()

	for _, root := range candidates {
		ok, err := executable(root)
		if err != nil {
			return Dirs{}, err
		}

		if ok {
			return EphemeralDirs(root), nil
		}
	}

	return Dirs{}, fmt.Errorf("every place an ephemeral run is kept is on a filesystem mounted noexec, "+
		"so the anchord it extracts could not run: %v.\n  Set CONFLUX_DIR to a directory on one that is not", candidates)
}

// executable reports whether a program extracted under root may run: whether the
// filesystem holding the nearest of root and its parents that exists is mounted to allow it.
func executable(root string) (bool, error) {
	for dir := root; ; dir = filepath.Dir(dir) {
		ok, err := mountAllowsExec(dir)
		if err == nil {
			return ok, nil
		}

		if !errors.Is(err, os.ErrNotExist) || filepath.Dir(dir) == dir {
			return false, fmt.Errorf("read the filesystem holding %s: %w", root, err)
		}
	}
}
