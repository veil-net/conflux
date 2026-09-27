// Package service registers conflux with the platform's boot manager: systemd,
// launchd, rc on the BSDs, or the Windows service control manager.
//
// One rule shapes the whole interface: Install registers and does not start. That is
// what lets `conflux install` put the service in place on a machine that has no
// configuration yet, so that a later `up` has somewhere to land.
package service

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Manager is one platform's boot manager.
type Manager interface {
	// Install registers the service to start at boot. Idempotent, and it does not
	// start anything.
	Install(exe string, args ...string) error

	// Remove deregisters it and deletes what registering it wrote, its log included.
	// Each step tolerates its own failure, so a half-removed service can always be
	// finished off.
	Remove() error

	Stop() error
	Restart() error

	Installed() (bool, error)

	// Describe is one line for `conflux status`.
	Describe() string

	// LogHint says where the service's output is, as something to run or open.
	LogHint() string
}

// New returns this platform's manager.
func New() (Manager, error) { return newManager() }

// Executable resolves the path the boot service should run.
//
// Symlinks are followed because a unit pointing at a symlink breaks the day somebody
// tidies it up, and the file we want recorded is the real one.
func Executable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("find this executable: %w", err)
	}

	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}

	return filepath.Clean(exe), nil
}

// WarnIfEphemeral reports a path a boot service should probably not be pointed at.
//
// A unit that runs /home/you/Downloads/conflux works perfectly until the download
// is cleaned up or the home directory is not mounted at boot, and then it fails in
// a way that looks like conflux being broken. Returns "" when the path is fine.
func WarnIfEphemeral(exe string) string {
	lowered := strings.ToLower(filepath.ToSlash(exe))

	for _, bad := range []string{"/tmp/", "/var/tmp/", "/downloads/", "/desktop/", "/private/tmp/"} {
		if strings.Contains(lowered, bad) {
			return fmt.Sprintf(
				"the boot service will run %s\n"+
					"  that path may not survive a reboot or a cleanup. Consider installing it first:\n"+
					"    %s", exe, installHint(exe))
		}
	}

	return ""
}

// installHint is the command that puts a downloaded binary somewhere permanent.
func installHint(exe string) string {
	if runtime.GOOS == "windows" {
		return `mkdir "$env:ProgramFiles\conflux"; copy ` + exe + ` "$env:ProgramFiles\conflux\conflux.exe"; ` +
			`& "$env:ProgramFiles\conflux\conflux.exe" install`
	}

	return "sudo install -m 0755 " + exe + " /usr/local/bin/conflux && sudo /usr/local/bin/conflux install"
}
