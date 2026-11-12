package daemon

import "golang.org/x/sys/unix"

// notDumpable marks this process not dumpable as well: the kernel then writes no core for it
// even to a core_pattern pipe, which RLIMIT_CORE does not bind, and nothing running as the
// same user may ptrace it or read its memory through /proc. anchord, which exec resets, has
// RLIMIT_CORE alone.
func notDumpable() { _ = unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0) }
