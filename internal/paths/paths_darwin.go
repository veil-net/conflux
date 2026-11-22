//go:build darwin

package paths

import "golang.org/x/sys/unix"

// holdDir is how a directory is opened to hold it: to read, which a directory this account may
// search and not read refuses, and is then held by its name (lookUp).
const holdDir = unix.O_RDONLY

// systemData is the folder the default root, DirName, is made in: /Library/Application Support, the
// system-wide half of the pair -- ~/Library is the per-user one, and conflux is per-machine.
func systemData() string { return "/Library/Application Support" }

// logsToFile is true: launchd writes the service's output to the file its plist names.
const logsToFile = true
