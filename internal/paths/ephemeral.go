package paths

import (
	"errors"
	"fmt"
	"io/fs"
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

// RuntimeFolder is the folder this account's ephemeral run keeps its root in (runtimeFolder), or why
// there is none: a variable so a test can keep it in a folder of its own (pathstest).
var RuntimeFolder = runtimeFolder

// EphemeralDirs are the roots of this account's ephemeral run, DirName in the runtime folder
// (RuntimeFolder), or why there are none: Config and State the root itself, though nothing is ever
// written as either, Run beneath it, and no log directory, since an ephemeral run's output goes to
// the terminal it runs in. They are an ephemeral run's, which no service serves. Nothing is read or
// made.
func EphemeralDirs() (Dirs, error) {
	folder, err := RuntimeFolder()
	if err != nil {
		return Dirs{}, err
	}

	root := filepath.Join(folder, DirName)

	return Dirs{Config: root, State: root, Run: filepath.Join(root, runName), ephemeral: true}, nil
}

// IsEphemeral reports whether d are an ephemeral run's (EphemeralDirs).
func (d Dirs) IsEphemeral() bool { return d.ephemeral }

// Ephemeral is the root a new ephemeral run is kept in (EphemeralDirs), made as conflux makes a root
// (EnsureAll): what is at its name and is not as conflux makes a root is removed as itself and the root
// made afresh. Refused, with nothing made, where the runtime folder is not there or is on a filesystem
// mounted noexec, where the anchord a run extracts could not run: there is no other place.
func Ephemeral() (Dirs, error) {
	d, err := EphemeralDirs()
	if err != nil {
		return Dirs{}, err
	}

	folder := filepath.Dir(d.State)

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
