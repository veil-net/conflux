// Package service registers conflux with the platform's boot manager.
//
// One rule shapes the whole interface: Install registers and does not start. The
// previous conflux conflated the two, which is why it had no way to express what
// `conflux install` is actually for -- putting the unit in place on a machine that
// has no configuration yet, so that a later `up` has somewhere to land.
package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ErrUnsupported means this platform has no integration yet. The BSDs return it,
// and the message names the command an operator should wire up by hand.
var ErrUnsupported = errors.New("conflux has no boot-service integration for this platform")

// Manager is one platform's boot manager.
type Manager interface {
	// Name is the unit, job or service name, for a status line.
	Name() string

	// Install registers the service to start at boot. Idempotent, and it does not
	// start anything.
	Install(exe string, args ...string) error

	// Remove deregisters it. Each step tolerates its own failure, so a half-removed
	// service can always be finished off.
	Remove() error

	Start() error
	Stop() error
	Restart() error

	Installed() (bool, error)
	Running() (bool, error)

	// Describe is one line for `conflux status`.
	Describe() string
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
					"    sudo install -m 0755 %s /usr/local/bin/conflux && sudo /usr/local/bin/conflux install",
				exe, exe)
		}
	}

	return ""
}
