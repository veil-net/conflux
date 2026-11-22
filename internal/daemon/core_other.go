//go:build !linux

package daemon

// noCoreDumps is Linux's, the one platform an ephemeral run, which asks for it, runs on.
func noCoreDumps() {}
