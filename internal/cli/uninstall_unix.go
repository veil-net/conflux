//go:build !windows

package cli

import "github.com/veil-net/conflux/internal/paths"

// removeInstallation removes the conflux install.sh put on PATH, and the link it made for
// sudo; this process may be that conflux, and its file goes all the same.
func removeInstallation() error {
	return removeInstalled(paths.InstalledExecutable(), paths.SudoLink())
}

// addPathEntry has nothing to add: /usr/local/bin, where conflux is installed, is on a
// terminal's PATH already.
func addPathEntry(string) error { return nil }
