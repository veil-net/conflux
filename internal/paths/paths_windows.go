//go:build windows

package paths

import (
	"os"
	"path/filepath"
)

const (
	// A named pipe, not a Unix socket: Windows has AF_UNIX but anchord's control
	// listener uses a pipe there, and a pipe name is not a filesystem path.
	socketName = "anchord.sock"

	// Not a real limit on Windows; kept so CheckSocketLen compiles and stays
	// harmlessly true. MAX_PATH is the practical bound and 260 is generous here.
	sockPathMax = 260
)

// platformDirs uses %ProgramData%, the machine-wide counterpart to %AppData%.
//
// Note that mode bits mean nothing here: %ProgramData% grants Users read by
// default, so the 0700 and 0600 elsewhere in conflux are no-ops on Windows and the
// protection comes from an explicit DACL set when the secret is written.
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
