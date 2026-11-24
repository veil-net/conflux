package paths

import (
	"os"
	"path"
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
// keeps its runtime files there, and otherwise somewhere a reboot empties -- the system's
// runtime directory, a user's own where the session names one ($XDG_RUNTIME_DIR, on any
// Unix), or else their temporary directory, which FreeBSD keeps across a reboot unless
// clear_tmp_enable is set. Per account, because the account running conflux decides what it
// may write: root's under the system's runtime directory, anybody else's under their own.
func EphemeralRoot() string {
	if rooted {
		return root + "-ephemeral"
	}

	return ephemeralRoot(runtime.GOOS, os.Geteuid(), os.Getenv)
}

// ephemeralRoot is EphemeralRoot on goos, for euid, with getenv's environment. A Unix's
// runtime directories are Unix paths, joined and judged absolute as Unix does (path, not
// filepath), so the answer for goos is the same on whatever host asks -- a test on Windows
// among them; on Unix the two are one. The temporary directory is the host's own, as
// os.TempDir is.
func ephemeralRoot(goos string, euid int, getenv func(string) string) string {
	switch {
	case goos == "windows":
		return filepath.Join(os.TempDir(), ephemeralName)
	case euid == 0 && goos == "linux":
		return path.Join("/run", ephemeralName)
	case euid == 0:
		return path.Join("/var/run", ephemeralName)
	}

	if xdg := getenv("XDG_RUNTIME_DIR"); xdg != "" && path.IsAbs(xdg) {
		return path.Join(xdg, ephemeralName)
	}

	return filepath.Join(os.TempDir(), ephemeralName+"-"+strconv.Itoa(euid))
}
