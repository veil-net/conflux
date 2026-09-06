//go:build darwin

package libexec

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// clearQuarantine strips com.apple.quarantine from a file conflux just wrote.
//
// The attribute is set on things downloaded, and a process that carries it can pass
// it to what it writes. On a binary a LaunchDaemon execs, that becomes a Gatekeeper
// prompt with no session to display it in -- so the daemon simply never starts.
// ENOATTR is the usual answer and means there was nothing to remove.
func clearQuarantine(path string) {
	_ = unix.Removexattr(path, "com.apple.quarantine")
}

func cannotExecute(dir string) string {
	return fmt.Sprintf(
		"the anchor binaries were extracted to %s but will not run from there.\n"+
			"  if this says \"killed: 9\", the binary's signature was rejected -- an Apple Silicon Mac\n"+
			"  refuses a Mach-O with no code signature at all.\n"+
			"  otherwise check that the filesystem is not mounted noexec.", dir)
}
