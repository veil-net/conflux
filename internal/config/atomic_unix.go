//go:build !windows

package config

import (
	"fmt"
	"io/fs"
	"os"
	"syscall"
)

// euid is the account conflux writes as: os.Geteuid, a variable only so a test that cannot give a
// file to another account can make its own file look like one.
var euid = os.Geteuid

// keep reports whether f, which holds what conflux writes, can stay as it is: only a file of
// the writer's own, since another account owning it can make it writable or write it whenever
// it likes. One of ours is given perm back where its mode is another, through the descriptor
// its bytes were read from, so the file compared is the one whose mode changes.
func keep(f *os.File, path string, perm fs.FileMode) (bool, error) {
	fi, err := f.Stat()
	if err != nil {
		return false, nil
	}

	if st, ok := fi.Sys().(*syscall.Stat_t); !ok || int(st.Uid) != euid() {
		return false, nil
	}

	if fi.Mode()&(fs.ModePerm|fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) == perm {
		return true, nil
	}

	if err := f.Chmod(perm); err != nil {
		return false, fmt.Errorf("chmod %s: %w", path, err)
	}

	return true, nil
}
