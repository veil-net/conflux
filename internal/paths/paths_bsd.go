//go:build freebsd || openbsd

package paths

import (
	"runtime"

	"golang.org/x/sys/unix"
)

const sockPathMax = 104 // sizeof(sockaddr_un.sun_path) on the BSDs

// holdDir is how a walk opens a directory to hold it: to read, which a directory this account may
// search and not read refuses, and the walk then holds by its name (lookUp).
const holdDir = unix.O_RDONLY

// systemData is the folder the default root, DirName, is made in: /var/db, where the BSDs keep a
// program's state.
func systemData() string { return "/var/db" }

// logsToFile is whether the service's output goes to a file conflux keeps: FreeBSD's daemon(8) writes
// it to one; OpenBSD's rc.d sends it to syslog.
const logsToFile = runtime.GOOS == "freebsd"
