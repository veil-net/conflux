package config

import (
	"io/fs"

	"github.com/veil-net/conflux/internal/paths"
)

// WriteFileAtomic replaces path with data, or leaves what was there, at perm, set on the descriptor
// before any content reaches it (paths.WriteAtomic).
func WriteFileAtomic(path string, data []byte, perm fs.FileMode) error {
	return paths.WriteAtomic(path, perm, -1, -1, data)
}

// WriteFileAtomicAs is WriteFileAtomic for a file that belongs to uid and gid, given to them on the
// descriptor before any content reaches it, as the mode is; -1 leaves either as the creating
// process's.
func WriteFileAtomicAs(path string, data []byte, perm fs.FileMode, uid, gid int) error {
	return paths.WriteAtomic(path, perm, uid, gid, data)
}
