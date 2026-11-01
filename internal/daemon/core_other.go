//go:build !linux && !windows

package daemon

// notDumpable is Linux's; RLIMIT_CORE is the whole of it here.
func notDumpable() {}
