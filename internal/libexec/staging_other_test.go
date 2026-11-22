//go:build !windows

package libexec

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"github.com/veil-net/conflux/internal/pathstest"
)

// othersInfo is a directory's FileInfo with another account as its owner.
type othersInfo struct {
	fs.FileInfo

	st syscall.Stat_t
}

func (o othersInfo) Sys() any { return &o.st }

// TestRemoveTemporaryLeavesAnotherAccountsCopy: on Unix the temporary directory is shared -- /tmp, sticky,
// which root may empty of anybody's -- so RemoveTemporary removes only what the account running it owns,
// and a folder named as Temporary names one that another account owns -- the copy one of its readers is
// running -- is left, and not listed.
func TestRemoveTemporaryLeavesAnotherAccountsCopy(t *testing.T) {
	parent := pathstest.Temporary(t, t.TempDir())
	mine, theirs := filepath.Join(parent, temporaryPrefix+"1"), filepath.Join(parent, temporaryPrefix+"2")

	for _, dir := range []string{mine, theirs} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	defer func(was func(string) (fs.FileInfo, error)) { lstat = was }(lstat)
	lstat = func(p string) (fs.FileInfo, error) {
		fi, err := os.Lstat(p)
		if err != nil || p != theirs {
			return fi, err
		}

		o := othersInfo{FileInfo: fi, st: *fi.Sys().(*syscall.Stat_t)}
		o.st.Uid = uint32(os.Geteuid() + 1)

		return o, nil
	}

	removed := RemoveTemporary()

	if _, err := os.Lstat(mine); !errors.Is(err, os.ErrNotExist) || !slices.Contains(removed, mine) {
		t.Errorf("RemoveTemporary left %s, its own (Lstat: %v), or did not say it removed it: %q", mine, err, removed)
	}

	if _, err := os.Lstat(theirs); err != nil || slices.Contains(removed, theirs) {
		t.Errorf("RemoveTemporary removed %s, another account's (Lstat: %v), or said it did: %q", theirs, err, removed)
	}
}
