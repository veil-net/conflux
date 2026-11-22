//go:build linux

package paths

import "golang.org/x/sys/unix"

// holdDir is how a directory is opened to hold it: as a path alone (O_PATH), which needs no
// right on the directory but to reach it, as a lookup through it needs, and serves fstat and the
// *at calls.
const holdDir = unix.O_PATH

// systemData is the folder the default root, DirName, is made in: /var/lib, the FHS's variable state
// a program maintains, rather than /usr, which is read-only in image-based and container deployments.
func systemData() string { return "/var/lib" }

// logsToFile is false: the service's output goes to journald through stderr, so there is no log
// directory.
const logsToFile = false
