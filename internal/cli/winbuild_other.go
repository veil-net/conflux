//go:build !windows

package cli

// tooOld refuses nothing here: only Windows has releases without the AF_UNIX sockets anchord's
// control socket needs.
func tooOld() error { return nil }
