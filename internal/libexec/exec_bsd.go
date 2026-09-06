//go:build freebsd || openbsd

package libexec

import "fmt"

// clearQuarantine has no meaning on the BSDs.
func clearQuarantine(string) {}

func cannotExecute(dir string) string {
	return fmt.Sprintf(
		"the anchor binaries were extracted to %s but will not run from there.\n"+
			"  check that the filesystem is not mounted noexec, and that no policy forbids execution there.\n"+
			"  set CONFLUX_DIR to a directory execution is permitted from.", dir)
}
