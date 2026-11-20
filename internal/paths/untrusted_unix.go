//go:build !windows

package paths

import (
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// OpenUntrusted is how a file in a directory another account can write is opened, by name
// or within an os.Root: to read, never through a symlink, and never blocking on a FIFO the
// name was made into. os.OpenFile adds O_CLOEXEC itself.
const OpenUntrusted = os.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK

// PlainFile reports whether fi, of a file opened with OpenUntrusted, is one to use: a
// regular file with no second name -- a hard link the account made to a file of root's
// would otherwise lead root to it -- and no more than max bytes.
func PlainFile(fi os.FileInfo, max int64) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)

	return fi.Mode().IsRegular() && ok && st.Nlink == 1 && fi.Size() <= max
}
