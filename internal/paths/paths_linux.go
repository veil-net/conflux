//go:build linux

package paths

const (
	socketName  = "anchord.sock"
	sockPathMax = 108 // sizeof(sockaddr_un.sun_path) on Linux
)

// platformDirs follows the FHS: configuration in /etc, variable state a program
// maintains in /var/lib, runtime files that do not survive a reboot in /run.
//
// /var/lib rather than /usr/libexec for the extracted binaries, because /usr is
// read-only in image-based and container deployments and /var/lib is precisely
// where "variable state a program maintains" belongs. Logs go to journald through
// stderr, so there is no log directory.
func platformDirs() Dirs {
	return Dirs{
		Config: "/etc/conflux",
		State:  "/var/lib/conflux",
		Run:    "/run/conflux",
	}
}
