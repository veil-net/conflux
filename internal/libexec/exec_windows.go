//go:build windows

package libexec

import "fmt"

// clearQuarantine has no Windows equivalent. The analogous problem there is
// SmartScreen and Defender, and neither is an attribute a process can clear.
func clearQuarantine(string) {}

func cannotExecute(dir string) string {
	return fmt.Sprintf(
		"the anchor binaries were extracted to %s but will not run from there.\n"+
			"  an endpoint protection product may have quarantined them: a program that writes and then\n"+
			"  runs a 29 MB executable is a shape scanners are suspicious of.\n"+
			"  check the Defender protection history, and exclude that directory if this is expected.", dir)
}
