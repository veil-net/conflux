//go:build darwin

package paths

const (
	socketName  = "anchord.sock"
	sockPathMax = 104 // sizeof(sockaddr_un.sun_path) on macOS
)

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
