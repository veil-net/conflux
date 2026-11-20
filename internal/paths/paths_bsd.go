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

// platformDirs uses /var/db for state, which is where the BSDs keep it, and
// /var/run rather than /run. FreeBSD's daemon(8) writes the service's output to a file
// in /var/log; OpenBSD's rc.d sends it to syslog.
func platformDirs() Dirs {
	d := Dirs{
		Config: "/usr/local/etc/conflux",
		State:  "/var/db/conflux",
		Run:    "/var/run/conflux",
	}

	if runtime.GOOS == "freebsd" {
		d.Log = "/var/log"
	}

	return d
}
