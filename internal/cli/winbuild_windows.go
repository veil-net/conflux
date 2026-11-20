//go:build windows

package cli

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// oldestBuild is the oldest Windows conflux runs on: Windows 10 version 1803, the first release
// with AF_UNIX sockets (from build 17063), which anchord's control socket is; on servers, Windows
// Server 2019.
const oldestBuild = 17134

// windowsBuild is this Windows's build number, which a test stands an older one in for.
var windowsBuild = func() uint32 { return windows.RtlGetVersion().BuildNumber }

// tooOld refuses a Windows older than oldestBuild, naming its build and the oldest conflux runs on:
// anchord could not listen on its control socket there.
func tooOld() error {
	build := windowsBuild()
	if build >= oldestBuild {
		return nil
	}

	return fmt.Errorf("this Windows, build %d, is too old for conflux, which needs Windows 10 version 1803 "+
		"(build %d) or later, Windows 11, or Windows Server 2019 or later: anchord's control socket is an "+
		"AF_UNIX socket, which Windows has from build 17063", build, oldestBuild)
}
