//go:build !windows

package paths

// InstalledExecutable is where install.sh puts conflux, and so where `conflux update` puts the
// next one and what `conflux uninstall` removes: on root's PATH and every user's, and fixed.
func InstalledExecutable() string { return "/usr/local/bin/conflux" }

// SudoLink is the link install.sh, and an update that installs conflux where there was none,
// make to InstalledExecutable where root's PATH under sudo does not find it (sudo's secure_path
// on Fedora and RHEL leaves /usr/local/bin out), kept only where root's PATH then finds it
// there, and which uninstall removes when it is that link.
func SudoLink() string { return "/usr/bin/conflux" }
