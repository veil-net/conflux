//go:build freebsd || openbsd

package paths

const (
	socketName  = "anchord.sock"
	sockPathMax = 104 // sizeof(sockaddr_un.sun_path) on the BSDs
)

// platformDirs uses /var/db for state, which is where the BSDs keep it, and
// /var/run rather than /run.
func platformDirs() Dirs {
	return Dirs{
		Config: "/usr/local/etc/conflux",
		State:  "/var/db/conflux",
		Run:    "/var/run/conflux",
	}
}
