package cli

import (
	"strings"

	"github.com/veil-net/conflux/internal/paths"
)

// staleEphemeral is root as an ephemeral run that was killed left it, if one did: there,
// with nobody holding its lock.
func staleEphemeral(root string) (paths.Dirs, bool) {
	d, run := ephemeralAt(root)

	return d, run == staleRun
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
