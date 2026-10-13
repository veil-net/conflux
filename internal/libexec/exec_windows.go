//go:build windows

package libexec

import "fmt"

func cannotExecute(dir string) string {
	return fmt.Sprintf(
		"the anchor binaries were extracted to %s but will not run from there.\n"+
			"  an endpoint protection product may have quarantined them: a program that writes and then\n"+
			"  runs a 30 MB executable is a shape scanners are suspicious of.\n"+
			"  check the Defender protection history, and exclude that directory if this is expected.", dir)
}
