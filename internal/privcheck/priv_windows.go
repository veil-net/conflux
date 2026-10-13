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
// A variable so a test can be the account that is refused.
var Elevated = func() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// Require refuses, with how to get the elevation that would work.
func Require(what, retry string) error {
	if Elevated() {
		return nil
	}

	return fmt.Errorf("%s needs Administrator.\n  %s", what, Retry(retry))
}

// Retry is a command as an Administrator would run it.
func Retry(cmd string) string {
	return "open PowerShell with \"Run as administrator\", then:  " + strings.TrimSpace(cmd)
}
