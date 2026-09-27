//go:build freebsd || openbsd

package paths

import "runtime"

const (
	socketName  = "anchord.sock"
	sockPathMax = 104 // sizeof(sockaddr_un.sun_path) on the BSDs
)

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
