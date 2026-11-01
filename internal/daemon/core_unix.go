//go:build !windows

package daemon

import "golang.org/x/sys/unix"

// noCoreDumps keeps this process, and every process it starts, from dumping core: what an
// ephemeral run holds in memory is the identity seed, and a core file would put it on disk.
// RLIMIT_CORE is inherited across fork and exec, so anchord starts under it too. Best effort:
// a limit the host will not lower leaves the run as it was.
func noCoreDumps() {
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
	notDumpable()
}
