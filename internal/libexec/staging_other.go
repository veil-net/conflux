//go:build !windows

package libexec

import (
	"errors"
	"fmt"
	"os"

	"github.com/veil-net/conflux/internal/paths"
)

// makeStaging makes a directory in root under a name beginning prefix that nobody can foresee: 0700,
// the extracting account's. A set is written in one before it takes its name.
func makeStaging(root, prefix string) (string, error) { return os.MkdirTemp(root, prefix+"*") }

// temporaryParents are where Temporary may make its directories, in the order temporaryDir chooses among
// them, which RemoveTemporary looks in: the system's temporary directory, and the user's cache directory,
// for a host that mounts the first noexec, as /tmp is on a hardened one.
func temporaryParents() []string {
	parents := []string{os.TempDir()}

	if cache, err := os.UserCacheDir(); err == nil {
		parents = append(parents, cache)
	}

	return parents
}

// temporaryDir makes the directory Temporary writes its copy in, as the account running conflux, and is
// how the copy is restricted: by the mode it is written with, here. It is made in the first of
// temporaryParents on a filesystem that lets it run, the user's cache directory made if it is not there
// yet; no other directory is made.
func temporaryDir() (string, func(string, bool) error, error) {
	candidates := temporaryParents()

	parent, err := paths.FirstExecutable(candidates)
	if errors.Is(err, paths.ErrNoExec) {
		return "", nil, fmt.Errorf("every temporary directory is on a filesystem mounted noexec, so the anchorctl "+
			"conflux runs could not run from it: %v.\n  Set TMPDIR to a directory on one that is not", candidates)
	}

	if err != nil {
		return "", nil, err
	}

	// The user's cache directory is the user's own, and one a fresh account has not made yet is
	// made. The system's temporary directory is not conflux's to make: one that is missing is
	// an error, as it is to everything else that writes there.
	if parent != candidates[0] {
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return "", nil, err
		}
	}

	dir, err := os.MkdirTemp(parent, temporaryPrefix+"*")

	return dir, paths.RestrictToOwner, err
}
