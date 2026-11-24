package cli

import (
	"errors"
	"io/fs"
	"os"
	"strings"

	"github.com/veil-net/conflux/internal/flock"
	"github.com/veil-net/conflux/internal/paths"
)

// staleEphemerals are the roots, among roots, an ephemeral run that was killed left behind:
// there, with nobody holding its lock.
func staleEphemerals(roots []string) []paths.Dirs {
	var stale []paths.Dirs

	for _, root := range roots {
		d := paths.EphemeralDirs(root)
		if _, err := os.Stat(d.ServeLockFile()); err != nil {
			continue
		}

		if held, err := flock.Held(d.ServeLockFile()); err == nil && !held {
			stale = append(stale, d)
		}
	}

	return stale
}

// removeInstalled removes the conflux the install script put at exe, and link where it is a
// link to exe -- the one install.sh makes for sudo -- leaving a file or a link of that name
// that is somebody else's.
func removeInstalled(exe, link string) error {
	errs := []error{removeIfThere(exe)}

	if link != "" {
		if target, err := os.Readlink(link); err == nil && target == exe {
			errs = append(errs, removeIfThere(link))
		}
	}

	return errors.Join(errs...)
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
