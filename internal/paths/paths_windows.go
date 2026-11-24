//go:build windows

package paths

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

// sizeof(sockaddr_un.sun_path) on Windows, and the limit anchord refuses past.
const sockPathMax = 108

// platformRoot is in ProgramData, the machine-wide counterpart to %AppData%.
//
// Mode bits mean nothing here -- ProgramData grants Users read and create by default
// -- so the protection comes from the ownership and DACL EnsureAll gives the root and
// everything beneath it inherits; see acl_windows.go.
func platformRoot() string {
	return filepath.Join(knownFolder(windows.FOLDERID_ProgramData, `C:\ProgramData`), ".conflux")
}

// knownFolder is where Windows keeps the folder id names, asked of the system rather than read
// from the environment, which is whoever started conflux's to set: a %ProgramData% or a
// %ProgramFiles% pointed elsewhere would move the root, or the conflux the installers put in
// place, into a directory of their choosing. fallback, Windows' own default, is for a lookup
// that fails.
func knownFolder(id *windows.KNOWNFOLDERID, fallback string) string {
	if dir, err := windows.KnownFolderPath(id, windows.KF_FLAG_DEFAULT); err == nil && dir != "" {
		return dir
	}

	return fallback
}
