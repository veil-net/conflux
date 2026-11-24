package paths

import (
	"os"
	"path/filepath"
)

// InstalledExecutable is where install.ps1 puts conflux, in a directory of its own on the
// machine's PATH, and so where `conflux update` puts the next one and what `conflux uninstall`
// removes, with the directory and its PATH entry: fixed.
func InstalledExecutable() string {
	pf := os.Getenv("ProgramFiles")
	if pf == "" {
		pf = `C:\Program Files`
	}

	return filepath.Join(pf, "conflux", "conflux.exe")
}

// SudoLink is nothing on Windows, which has no sudo to find conflux for.
func SudoLink() string { return "" }
