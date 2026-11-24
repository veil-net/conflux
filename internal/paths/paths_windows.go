//go:build windows

package paths

import (
	"os"
	"path/filepath"
)

// sizeof(sockaddr_un.sun_path) on Windows, and the limit anchord refuses past.
const sockPathMax = 108

// writesLog is true: the SCM keeps no output of its own, so conflux writes the service's.
const writesLog = true

// platformRoot is in %ProgramData%, the machine-wide counterpart to %AppData%.
//
// Mode bits mean nothing here -- %ProgramData% grants Users read and create by default
// -- so the protection comes from the ownership and DACL EnsureAll gives the root and
// everything beneath it inherits; see acl_windows.go.
func platformRoot() string {
	data := os.Getenv("ProgramData")
	if data == "" {
		data = `C:\ProgramData`
	}

	return filepath.Join(data, ".conflux")
}
