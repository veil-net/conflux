//go:build !windows

package libexec

import (
	"os"

	"github.com/veil-net/conflux/internal/paths"
)

// makeStaging makes a directory in root under a name beginning prefix that nobody can foresee: 0700,
// the extracting account's. A set is written in one before it takes its name.
func makeStaging(root, prefix string) (string, error) { return os.MkdirTemp(root, prefix+"*") }

// temporaryDir makes the directory temporary writes its copy in, the account's own
// (usersTemporaryDir), and is how the copy is restricted: by the mode it is written with, here.
func temporaryDir() (string, func(string, bool) error, error) {
	dir, err := usersTemporaryDir()

	return dir, paths.RestrictToOwner, err
}
