package paths

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

// An ephemeral run keeps nothing of the machine's: no configuration, no identity, no
// state, no boot service. What it needs while it runs -- the lock that makes it the only
// one, the bearer token and the socket, the record of the anchord it started, and, where
// the pair cannot run from memory, the extracted pair -- goes in a root of its own, which a
// reboot empties, and the root is removed when the run ends. Fixed rather than drawn per
// run, so that a second run is refused by the lock, the next run can stop an anchord a
// killed one left, and `conflux status` from another terminal can find the socket.

// ephemeralName is the root's name, in the system's or the user's runtime directory.
const ephemeralName = "conflux-ephemeral"

// Ephemeral is the root an ephemeral run of this account is kept in. Nothing is ever written
// there as a configuration, a state or an identity, and there is no log: an ephemeral run's
// output goes to the terminal it runs in.
func Ephemeral() Dirs { return Dirs{Root: EphemeralRoot()} }

// EphemeralRoot is where this account's ephemeral run is kept: in memory where the platform
// keeps its runtime files there, and everywhere somewhere a reboot empties. Per account,
// because the account running conflux decides what it may write: root's under the system's
// runtime directory, anybody else's under their own.
func EphemeralRoot() string {
	if rooted {
		return root + "-ephemeral"
	}

	return ephemeralRoot(os.Geteuid(), os.Getenv)
}

func ephemeralRoot(euid int, getenv func(string) string) string {
	switch {
	case runtime.GOOS == "windows":
		return filepath.Join(os.TempDir(), ephemeralName)
	case euid == 0 && runtime.GOOS == "linux":
		return filepath.Join("/run", ephemeralName)
	case euid == 0:
		return filepath.Join("/var/run", ephemeralName)
	}

	if xdg := getenv("XDG_RUNTIME_DIR"); runtime.GOOS == "linux" && xdg != "" && filepath.IsAbs(xdg) {
		return filepath.Join(xdg, ephemeralName)
	}

	return filepath.Join(os.TempDir(), ephemeralName+"-"+strconv.Itoa(euid))
}
