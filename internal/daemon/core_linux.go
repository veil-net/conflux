package daemon

import "golang.org/x/sys/unix"

// noCoreDumps keeps this process, and every process it starts, from dumping core: what an
// ephemeral run holds in memory is the identity seed, and a core file would put it on disk.
// RLIMIT_CORE is inherited across fork and exec, so anchord starts under it too. This process
// is marked not dumpable as well: the kernel then writes no core for it even to a core_pattern
// pipe, which RLIMIT_CORE does not bind, and nothing running as the same user may ptrace it or
// read its memory through /proc. anchord, which exec resets, has RLIMIT_CORE alone. Best effort:
// a limit the host will not lower leaves the run as it was.
func noCoreDumps() {
	_ = unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
	_ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}
