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

// updateLink is the link an update that installs conflux where there was none makes for sudo,
// as install.sh makes it: a variable, so a test points it elsewhere.
var updateLink = paths.SudoLink

// removeInstallation removes the conflux install.sh put on PATH, and the link it made for
// sudo; this process may be that conflux, and its file goes all the same.
func removeInstallation() error {
	return removeInstalled(paths.InstalledExecutable(), paths.SudoLink())
}

// putOnPath has root find exe, a conflux an update installed where there was none, by name, as
// install.sh's link does. /usr/local/bin is on a terminal's PATH, but not on every root's: where
// the conflux this update's own PATH finds -- root's, sudo's secure_path on Fedora and RHEL -- is
// not exe, its directory left out or another conflux found first, the link for sudo (updateLink)
// is made to exe, and kept only where that PATH, asked again, finds exe through it. A link that
// PATH does not find exe through, made now or by an install before, does nothing, so it goes,
// and what the PATH finds instead is said (missed). A file or a link of that name that is not
// that link is left alone, and said, as uninstall leaves it.
func putOnPath(exe string) error {
	found, ok := rootFinds(exe)
	if ok {
		return nil
	}

	link := updateLink()

	if !linksTo(link, exe) {
		why := fmt.Sprintf("root's PATH leaves %s out", filepath.Dir(exe))
		if found != "" {
			why = fmt.Sprintf("root's PATH finds %s instead", found)
		}

		if _, err := os.Lstat(link); err == nil {
			return notOurs(found, link, exe, why)
		}

		if err := os.Symlink(exe, link); err != nil {
			return fmt.Errorf("%s, so type %s by its full path under sudo: %w", why, exe, err)
		}

		if found, ok = rootFinds(exe); ok {
			ui.Printf("Linked %s to it, since %s.\n", link, why)

			return nil
		}
	}

	return errors.Join(missed(found, link, exe), removeIfThere(link))
}

// rerun is the way out where root's PATH finds a conflux that is not exe in place of it: that
// one removed, the installer, install.sh, links exe again, which an update, finding exe
// installed, never does.
const rerun = "remove it and run the installer again, or type %s by its full path under sudo"

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
// it: another conflux before the link's directory, or, finding none, that directory left out too,
// where only exe's full path helps.
func missed(found, link, exe string) error {
	if found == "" {
		return fmt.Errorf("root's PATH leaves %s out too: type %s by its full path under sudo", filepath.Dir(link), exe)
	}

	return fmt.Errorf("root's PATH finds %s before %s: "+rerun, found, filepath.Dir(link), exe)
}

// notOurs says that link, the name of the link for sudo, is a file conflux did not make, and why
// root's PATH does not find exe: where what it finds is that file -- through the link's own
// directory, however spelled, as a merged /bin is /usr/bin -- removing it lets the installer link
// exe there; otherwise why, which another conflux found first, or exe's directory left out, keeps.
func notOurs(found, link, exe, why string) error {
	if found != "" && sameFile(filepath.Dir(found), filepath.Dir(link)) {
		return fmt.Errorf("%s is not conflux's, and root's PATH finds it rather than %s: "+rerun, link, exe, exe)
	}

	return fmt.Errorf("%s is not conflux's, and %s: type %s by its full path under sudo", link, why, exe)
}
