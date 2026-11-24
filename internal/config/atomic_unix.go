//go:build !windows

package config

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"syscall"
)

// euid is the account conflux writes as: os.Geteuid, a variable only so a test that cannot give a
// file to another account can make its own file look like one.
var euid = os.Geteuid

// WriteFileIfChanged is WriteFileAtomic, with perm, unless path holds data already, and reports
// whether it wrote. What conflux puts back at every start -- the boot service's registration
// above all -- is written only where it was changed, so an unchanged file keeps its inode and
// its mtime and nothing watching it sees a change. One that holds data with another mode is
// given perm back where it is, which is no write: a registration made group- or world-writable
// since is the service manager running whatever its writer names. One that holds data and
// another account owns is written: its owner can make it writable or write it whenever it
// likes, and the file written in its place is the writer's.
//
// Unix alone: every registration it writes is a file a Unix service manager reads, and the
// SCM keeps the Windows service's itself.
func WriteFileIfChanged(path string, data []byte, perm fs.FileMode) (bool, error) {
	switch same, err := holds(path, data, perm); {
	case err != nil:
		return false, err
	case same:
		return false, nil
	}

	if err := WriteFileAtomic(path, data, perm); err != nil {
		return false, err
	}

	return true, nil
}

// holds reports whether path holds data already, in a file that can stay: only a file of the
// writer's own, since another account owning it can make it writable or write it whenever it
// likes. One of ours is given perm back where its mode is another, through the descriptor its
// bytes were read from, so the file compared is the one whose mode changes. A file that cannot
// be opened or read holds nothing, and is written.
func holds(path string, data []byte, perm fs.FileMode) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, nil
	}
	defer f.Close()

	// One byte past data is enough to know a longer file differs.
	cur, err := io.ReadAll(io.LimitReader(f, int64(len(data))+1))
	if err != nil || !bytes.Equal(cur, data) {
		return false, nil
	}

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
