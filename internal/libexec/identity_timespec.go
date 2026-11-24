//go:build darwin || freebsd

package libexec

import (
	"fmt"
	"os"
	"syscall"
)

// fileIdentity is what changes when a file's content does or it is replaced: its inode, and
// its modification and change times, the second of which no write can set back.
func fileIdentity(fi os.FileInfo) string {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fi.ModTime().String()
	}

	return fmt.Sprintf("%d %d %d.%d", st.Ino, fi.ModTime().UnixNano(), st.Ctimespec.Sec, st.Ctimespec.Nsec)
}
