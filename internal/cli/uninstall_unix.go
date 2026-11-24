//go:build !windows

package cli

import (
	"errors"
	"fmt"
	"io/fs"
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

// removeInstalled removes the conflux the install script put at exe, and link where it is a
// link to exe -- the one install.sh makes for sudo -- leaving a file or a link of that name
// that is somebody else's.
func removeInstalled(exe, link string) error {
	errs := []error{removeIfThere(exe)}

	if linksTo(link, exe) {
		errs = append(errs, removeIfThere(link))
	}

	return errors.Join(errs...)
}

// linksTo reports whether link is the link for sudo to exe, as install.sh and an update make it:
// a symbolic link whose target is exe as written, so a link of that name to anything else,
// another spelling of exe included, is somebody else's.
func linksTo(link, exe string) bool {
	target, err := os.Readlink(link)

	return err == nil && target == exe
}

func removeIfThere(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	return nil
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

// relink is the way out where root's PATH finds a conflux that is not exe in place of it: that
// one removed, link, the link for sudo, made to exe by hand, which an update, finding exe
// installed, never makes. Not install.sh run again, as install.sh says: it fetches the latest
// release, and would move a dev build off its channel.
func relink(exe, link string) string {
	return fmt.Sprintf("remove it, then link the installed conflux for sudo (sudo ln -s %s %s), or type %s by its full path under sudo", exe, link, exe)
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
// it: another conflux before the link's directory, which removed lets exe be linked by hand
// (relink), or, where exe's own directory is on that PATH ahead of the link's, lets that PATH
// find exe with no link at all, a link there never being reached; or, finding none, that
// directory left out too, where only exe's full path helps. Directories are compared as files
// (sameFile), never by how they are spelled.
func missed(found, link, exe string) error {
	if found == "" {
		return fmt.Errorf("root's PATH leaves %s out too: type %s by its full path under sudo", filepath.Dir(link), exe)
	}

	for _, d := range filepath.SplitList(os.Getenv("PATH")) {
		if sameFile(d, filepath.Dir(link)) {
			break
		}

		if sameFile(d, filepath.Dir(exe)) {
			return fmt.Errorf("root's PATH finds %s before %s: remove it; root's PATH then finds %s", found, filepath.Dir(exe), exe)
		}
	}

	return fmt.Errorf("root's PATH finds %s before %s: %s", found, filepath.Dir(link), relink(exe, link))
}

// notOurs says that link, the name of the link for sudo, is a file conflux did not make, and why
// root's PATH does not find exe: where what it finds is that file -- through the link's own
// directory, however spelled, as a merged /bin is /usr/bin -- removing it lets exe be linked
// there (relink); otherwise why, which another conflux found first, or exe's directory left out,
// keeps.
func notOurs(found, link, exe, why string) error {
	if found != "" && sameFile(filepath.Dir(found), filepath.Dir(link)) {
		return fmt.Errorf("%s is not conflux's, and root's PATH finds it rather than %s: %s", link, exe, relink(exe, link))
	}

	return fmt.Errorf("%s is not conflux's, and %s: type %s by its full path under sudo", link, why, exe)
}
