//go:build !windows

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"

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
// this update's own PATH, root's -- sudo's secure_path, on Fedora and RHEL -- leaves exe's
// directory out, the link for sudo (updateLink) is made to exe, and a file or a link of that
// name that is not that link is left alone, and said, as uninstall leaves it.
func putOnPath(exe string) error {
	dir := filepath.Dir(exe)

	names := func(e string) bool { return filepath.Clean(e) == dir }
	if slices.ContainsFunc(filepath.SplitList(os.Getenv("PATH")), names) {
		return nil
	}

	link := updateLink()

	if target, err := os.Readlink(link); err == nil && target == exe {
		return nil
	}

	if _, err := os.Lstat(link); err == nil {
		return fmt.Errorf("%s is not conflux's, so root's PATH, which leaves %s out, finds that one first", link, dir)
	}

	if err := os.Symlink(exe, link); err != nil {
		return fmt.Errorf("root's PATH leaves %s out, so type %s by its full path under sudo: %w", dir, exe, err)
	}

	ui.Printf("Linked %s to it, since root's PATH leaves %s out.\n", link, dir)

	return nil
}
