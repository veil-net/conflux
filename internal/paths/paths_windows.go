//go:build windows

package paths

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

// logsToFile is true: the service writes its output to a file of its own (serve --log).
const logsToFile = true

// systemData is the folder the installation's root, DirName, is made in, and an elevated reader's
// temporary copy of anchorctl (libexec's Temporary) too: %ProgramData%, the machine-wide counterpart to
// %AppData%. Mode bits mean nothing here -- %ProgramData% grants Users read and create by default -- so
// the protection comes from the ownership and DACL EnsureAll gives the root and everything beneath it
// inherits; see acl_windows.go.
//
// It is \ProgramData on the volume the system's Windows directory is on, which Windows supports no other
// place for, and C: where that cannot be read: never the environment's ProgramData. An
// elevated process's environment is built from the user's registry, HKCU\Environment among it, which that
// user's processes that are not elevated may write, and a ProgramData of theirs would lead the roots an
// elevated conflux makes, and the anchorctl it runs, into a folder they own. GetSystemWindowsDirectory
// reads no environment: it is the system root the kernel publishes, read-only, in the page of shared user
// data every process maps, and kernel32 is loaded from the system directory, never the search path.
func systemData() string {
	dir, err := windows.GetSystemWindowsDirectory()

	vol := filepath.VolumeName(dir)
	if err != nil || vol == "" {
		vol = "C:"
	}

	return vol + `\ProgramData`
}
