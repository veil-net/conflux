package libexec

import (
	"errors"
	"io/fs"
	"math/rand/v2"
	"path/filepath"
	"strconv"

	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/privcheck"
)

// makeStaging makes a directory in root under a name beginning prefix, drawn as os.MkdirTemp draws one,
// with Restrict's ownership and DACL set as it is created (paths.MakeRestricted): SYSTEM's and the
// Administrators', never for an instant what root passes on. A name taken is drawn again, as often as
// os.MkdirTemp would. A set is written in one before it takes its name, and an elevated process's
// temporary copy of anchorctl in another (temporaryDir).
func makeStaging(root, prefix string) (string, error) {
	for try := 0; ; try++ {
		dir := filepath.Join(root, prefix+strconv.FormatUint(uint64(rand.Uint32()), 10))

		if err := paths.MakeRestricted(dir); !errors.Is(err, fs.ErrExist) || try == 9999 {
			return dir, err
		}
	}
}

// temporaryDir makes the directory Temporary writes its copy in, and is how the copy is restricted. An
// elevated process -- an administrator's, or SYSTEM's -- makes a folder of its own in %ProgramData%,
// SYSTEM's and the Administrators' from the moment it exists (makeStaging), which Users may make nothing
// in nor remove, and restricts the copy to them alike (paths.Restrict): the account's own %TEMP%, and a
// copy granted to it, are what its processes that are not elevated may change, between the write and
// the run, for the elevated one to run. One that is not elevated writes in the account's own temporary
// directory (usersTemporaryDir), the copy granted to the account (paths.RestrictToOwner), since a copy
// Restrict guards is one it could not run.
func temporaryDir() (string, func(string, bool) error, error) {
	if !privcheck.Elevated() {
		dir, err := usersTemporaryDir(usersTemporaryParents())

		return dir, paths.RestrictToOwner, err
	}

	dir, err := makeStaging(paths.ProgramData(), temporaryPrefix)

	return dir, paths.Restrict, err
}

// temporaryParents are where Temporary may make its directories for the account running conflux, which
// RemoveTemporary looks in: the account's own (usersTemporaryParents), where its processes that are not
// elevated make them, and, for an elevated process, which makes its own in %ProgramData%, that first.
func temporaryParents() []string {
	if privcheck.Elevated() {
		return append([]string{paths.ProgramData()}, usersTemporaryParents()...)
	}

	return usersTemporaryParents()
}
