//go:build windows

package privcheck

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
)

// Elevated reports whether the process token is elevated. A member of
// Administrators running without elevation is not enough: the checks conflux makes
// are about what it can actually do, not what the account could do if asked.
func Elevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

func Describe() string {
	if Elevated() {
		return "elevated"
	}

	return "not elevated"
}

func Require(what, retry string) error {
	if Elevated() {
		return nil
	}

	return fmt.Errorf(
		"%s needs Administrator.\n"+
			"  open PowerShell with \"Run as administrator\", then:  %s", what, strings.TrimSpace(retry))
}
