package paths

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// An ephemeral run, Linux's alone, keeps nothing of the machine's: no configuration, no identity, no
// state, no boot service. What it needs while it runs -- the lock that makes it the only one, the
// bearer token and the socket, the record of the anchord it started, and the extracted pair it runs --
// goes in a root of its own, DirName in the system's runtime folder, a filesystem in memory the system
// empties at boot, and the root is removed when the run ends. Fixed rather than drawn per run, so that
// a second run is refused by the lock, the next run can stop an anchord a killed one left, and
// `conflux status` from another terminal can find the socket. It is never an installation's root,
// which is in the system's data folder.

// The runtime folder is runtimeFolder here, unless a test keeps it in a folder of its own.
func init() { RuntimeFolder = runtimeFolder }

// EphemeralDirs are the roots of this account's ephemeral run, DirName in the runtime folder
// (RuntimeFolder), or why there are none: no log directory (LogDir), since an ephemeral run's output
// goes to the terminal it runs in, and no configuration, identity or state is ever written in it. They
// are an ephemeral run's, which no service serves. Nothing is read or made.
func EphemeralDirs() (Dirs, error) {
	folder, err := RuntimeFolder()
	if err != nil {
		return Dirs{}, err
	}

	return Dirs{Root: filepath.Join(folder, DirName), ephemeral: true}, nil
}

// Ephemeral is the root a new ephemeral run is kept in (EphemeralDirs), made as conflux makes a root
// (EnsureAll): what is at its name and is not as conflux makes a root is removed as itself and the root
// made afresh. Refused, with nothing made, where the runtime folder is not there or is on a filesystem
// mounted noexec, where the anchord a run extracts could not run: there is no other place.
func Ephemeral() (Dirs, error) {
	d, err := EphemeralDirs()
	if err != nil {
		return Dirs{}, err
	}

	folder := filepath.Dir(d.Root)

	switch ok, err := allowsExec(folder); {
	case errors.Is(err, fs.ErrNotExist):
		return Dirs{}, fmt.Errorf("%s, where an ephemeral run keeps its root, is not there", folder)
	case err != nil:
		return Dirs{}, fmt.Errorf("read the filesystem holding %s: %w", folder, err)
	case !ok:
		return Dirs{}, fmt.Errorf("%s, where an ephemeral run keeps its root, is on a filesystem mounted noexec, "+
			"so the anchord it extracts could not run there", folder)
	}

	return d, d.EnsureAll()
}

// runtimeFolder is the folder an ephemeral run keeps its root in, a filesystem in memory the system
// empties at boot: /run as root, and for anybody else their own runtime directory, $XDG_RUNTIME_DIR,
// refused where that is not set, or is not an absolute path.
func runtimeFolder() (string, error) {
	if os.Geteuid() == 0 {
		return "/run", nil
	}

	xdg := os.Getenv("XDG_RUNTIME_DIR")
	if xdg == "" || !filepath.IsAbs(xdg) {
		return "", errors.New("an ephemeral run keeps its root in your runtime directory, and XDG_RUNTIME_DIR does " +
			"not name one: run it from a login session that sets it (systemd-logind does), or as root, in /run")
	}

	return xdg, nil
}
