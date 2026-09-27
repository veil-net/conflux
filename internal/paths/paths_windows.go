//go:build windows

package paths

import (
	"os"
	"path/filepath"
)

const (
	// An AF_UNIX socket, as everywhere else: anchord listens on one on Windows too.
	socketName = "anchord.sock"

	// sizeof(sockaddr_un.sun_path) on Windows, and the limit anchord refuses past.
	sockPathMax = 108
)

// platformDirs uses %ProgramData%, the machine-wide counterpart to %AppData%.
//
// Mode bits mean nothing here -- %ProgramData% grants Users read and create by default
// -- so the protection comes from the ownership and DACL EnsureAll gives the root and
// everything beneath it inherits; see acl_windows.go.
func platformDirs() Dirs {
	root := os.Getenv("ProgramData")
	if root == "" {
		root = `C:\ProgramData`
	}

	root = filepath.Join(root, "conflux")

	return Dirs{
		Config: root,
		State:  root,
		Run:    filepath.Join(root, "run"),
		Log:    filepath.Join(root, "logs"),
	}
}
