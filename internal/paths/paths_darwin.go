//go:build darwin

package paths

import "golang.org/x/sys/unix"

const sockPathMax = 104 // sizeof(sockaddr_un.sun_path) on macOS

// holdDir is how a walk opens a directory to hold it: to read, which a directory this account may
// search and not read refuses, and the walk then holds by its name (lookUp).
const holdDir = unix.O_RDONLY

// systemData is the folder the default root, DirName, is made in: /Library/Application Support, the
// system-wide half of the pair -- ~/Library is the per-user one, and conflux is per-machine.
func systemData() string { return "/Library/Application Support" }

// logsToFile is true: launchd writes the service's output to the file its plist names.
const logsToFile = true
