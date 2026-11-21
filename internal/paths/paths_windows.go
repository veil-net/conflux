//go:build windows

package paths

import (
	"os"
	"path/filepath"
)

// sizeof(sockaddr_un.sun_path) on Windows, and the limit anchord refuses past.
const sockPathMax = 108

// platformDirs uses %ProgramData%, the machine-wide counterpart to %AppData%.
//
// Mode bits mean nothing here -- %ProgramData% grants Users read and create by default
// -- so the protection comes from the ownership and DACL EnsureAll gives the root and
// everything beneath it inherits; see acl_windows.go.
func platformDirs() Dirs {
	root := filepath.Join(ProgramData(), "conflux")

	return Dirs{
		Config: root,
		State:  root,
		Run:    filepath.Join(root, runName),
		Log:    filepath.Join(root, "logs"),
	}
}

// ProgramData is %ProgramData%, which the platform's roots, an ephemeral run's and an elevated reader's
// temporary copy of anchorctl (libexec's Temporary) are kept in.
func ProgramData() string {
	if root := os.Getenv("ProgramData"); root != "" {
		return root
	}

	return `C:\ProgramData`
}
