//go:build !windows

package config

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// OpenUntrusted is how a file in a directory another account can write is opened: never
// through a symlink, and never blocking on a FIFO the name was made into.
const OpenUntrusted = os.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK

// Untrusted reports whether fi, the file a name opened with OpenUntrusted, is one conflux
// reads: a regular file with no second name -- which a hard link the account made to a file
// of root's would be -- and no more than max bytes.
func Untrusted(fi os.FileInfo, max int64) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)

	return fi.Mode().IsRegular() && ok && st.Nlink == 1 && fi.Size() <= max
}

// oneName is asked nothing more here: a FileInfo carries the link count, which Untrusted read.
func oneName(*os.File) bool { return true }
