//go:build darwin

package paths

const sockPathMax = 104 // sizeof(sockaddr_un.sun_path) on macOS

// writesLog is true: launchd keeps no output of its own, so conflux writes the service's.
const writesLog = true

// platformRoot is under /Library/Application Support, the system-wide half of the pair --
// ~/Library is the per-user one, and conflux is per-machine.
func platformRoot() string { return "/Library/Application Support/.conflux" }
