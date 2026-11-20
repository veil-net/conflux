//go:build darwin

package paths

import "golang.org/x/sys/unix"

const sockPathMax = 104 // sizeof(sockaddr_un.sun_path) on macOS

// holdDir is how a walk opens a directory to hold it: to read, which a directory this account may
// search and not read refuses, and the walk then holds by its name (lookUp).
const holdDir = unix.O_RDONLY

// platformDirs puts everything a system daemon owns under
// /Library/Application Support, which is the system-wide half of the pair --
// ~/Library is the per-user one, and conflux is per-machine.
func platformDirs() Dirs {
	const root = "/Library/Application Support/conflux"

	return Dirs{
		Config: root,
		State:  root,
		Run:    "/var/run/conflux",
		Log:    "/var/log",
	}
}
