//go:build !windows

package cli

import (
	"errors"
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
// is made to exe, and kept only where that PATH, asked again, finds exe through it. Where it
// finds another conflux before the link's directory, the link would do nothing, so it goes again
// and the other is named, as it is beside a link made before. A file or a link of that name that
// is not that link is left alone, and said, as uninstall leaves it.
func putOnPath(exe string) error {
	found, ok := rootFinds(exe)
	if ok {
		return nil
	}

	why := fmt.Sprintf("root's PATH leaves %s out", filepath.Dir(exe))
	if found != "" {
		why = fmt.Sprintf("root's PATH finds %s instead", found)
	}

	link := updateLink()

	if target, err := os.Readlink(link); err == nil && target == exe {
		return missed(found, link, exe)
	}

	if _, err := os.Lstat(link); err == nil {
		return fmt.Errorf("%s is not conflux's, and %s: type %s by its full path under sudo", link, why, exe)
	}

	if err := os.Symlink(exe, link); err != nil {
		return fmt.Errorf("%s, so type %s by its full path under sudo: %w", why, exe, err)
	}

	if found, ok := rootFinds(exe); !ok {
		return errors.Join(missed(found, link, exe), removeIfThere(link))
	}

	ui.Printf("Linked %s to it, since %s.\n", link, why)

	return nil
}

// rootFinds is the conflux this process's PATH, root's, finds by name, or "" for none, and
// whether that is exe: asked of the file, through any link, by sameFile.
func rootFinds(exe string) (found string, ok bool) {
	found, err := exec.LookPath("conflux")
	if err != nil {
		return "", false
	}

	return found, sameFile(found, exe)
}

// missed says why root's PATH, which finds found, does not find exe through link, the link to
// it: another conflux before the link's directory, or, finding none, that directory left out too.
func missed(found, link, exe string) error {
	if found == "" {
		return fmt.Errorf("root's PATH leaves %s out too: type %s by its full path under sudo", filepath.Dir(link), exe)
	}

	return fmt.Errorf("root's PATH finds %s before %s: remove it, or type %s by its full path under sudo",
		found, filepath.Dir(link), exe)
}
