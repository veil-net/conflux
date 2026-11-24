package paths

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

// InstalledExecutable is where install.ps1 puts conflux, in a directory of its own on the
// machine's PATH, and so where `conflux update` puts the next one and what `conflux uninstall`
// removes, with the directory and its PATH entry: fixed, in Program Files as Windows keeps it.
func InstalledExecutable() string {
	return filepath.Join(knownFolder(windows.FOLDERID_ProgramFiles, `C:\Program Files`), "conflux", "conflux.exe")
}

// SudoLink is nothing on Windows, which has no sudo to find conflux for.
func SudoLink() string { return "" }
