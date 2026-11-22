//go:build freebsd || openbsd

package paths

import (
	"runtime"

	"golang.org/x/sys/unix"
)

// holdDir is how a directory is opened to hold it: to read, which a directory this account may
// search and not read refuses, and is then held by its name (lookUp).
const holdDir = unix.O_RDONLY

// systemData is the folder the default root, DirName, is made in: /var/db, where the BSDs keep a
// program's state.
func systemData() string { return "/var/db" }

// logsToFile is whether the service's output goes to a file conflux keeps: FreeBSD's daemon(8) writes
// it to one; OpenBSD's rc.d sends it to syslog.
const logsToFile = runtime.GOOS == "freebsd"
