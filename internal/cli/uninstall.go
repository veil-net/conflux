package cli

import (
	"errors"
	"io/fs"
	"os"
	"strings"

	"github.com/veil-net/conflux/internal/paths"
)

// staleEphemeral is root as an ephemeral run that was killed left it, if one did: there,
// with nobody holding its lock.
func staleEphemeral(root string) (paths.Dirs, bool) {
	d, run := ephemeralAt(root)

	return d, run == staleRun
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

// withoutDir is a PATH, as Windows writes it, with every entry naming dir taken out: compared
// without regard to case or a trailing backslash, as Windows compares them.
func withoutDir(path, dir string) string {
	want := strings.TrimRight(dir, `\`)

	var kept []string

	for e := range strings.SplitSeq(path, ";") {
		if e != "" && !strings.EqualFold(strings.TrimRight(e, `\`), want) {
			kept = append(kept, e)
		}
	}

	return strings.Join(kept, ";")
}

// withDir is a PATH, as Windows writes it, with dir added at its end where no entry names it
// already, compared as withoutDir compares them: what install.ps1 writes.
func withDir(path, dir string) string {
	want := strings.TrimRight(dir, `\`)

	for e := range strings.SplitSeq(path, ";") {
		if strings.EqualFold(strings.TrimRight(e, `\`), want) {
			return path
		}
	}

	if path = strings.TrimRight(path, ";"); path == "" {
		return dir
	}

	return path + ";" + dir
}
