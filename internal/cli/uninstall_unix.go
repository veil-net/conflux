//go:build !windows

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/ui"
)

// removeInstallation removes the conflux install.sh put on PATH, and the link it made for
// sudo; this process may be that conflux, and its file goes all the same.
func removeInstallation() error {
	return removeInstalled(paths.InstalledExecutable(), paths.SudoLink())
}

// putOnPath has root find exe, a conflux an update installed where there was none, by name, as
// install.sh's link does. /usr/local/bin is on a terminal's PATH, but not on every root's: where
// the conflux this update's own PATH finds -- root's, sudo's secure_path on Fedora and RHEL -- is
// not exe, its directory left out or another conflux found first, the link for sudo (updateLink)
// is made to exe, and a file or a link of that name that is not that link is left alone, and
// said, as uninstall leaves it.
func putOnPath(exe string) error {
	found, err := exec.LookPath("conflux")
	if err == nil && sameFile(found, exe) {
		return nil
	}

	why := fmt.Sprintf("root's PATH leaves %s out", filepath.Dir(exe))
	if err == nil {
		why = fmt.Sprintf("root's PATH finds %s instead", found)
	}

	link := updateLink()

	if target, err := os.Readlink(link); err == nil && target == exe {
		return nil
	}

	if _, err := os.Lstat(link); err == nil {
		return fmt.Errorf("%s is not conflux's, and %s: type %s by its full path under sudo", link, why, exe)
	}

	if err := os.Symlink(exe, link); err != nil {
		return fmt.Errorf("%s, so type %s by its full path under sudo: %w", why, exe, err)
	}

	ui.Printf("Linked %s to it, since %s.\n", link, why)

	return nil
}
