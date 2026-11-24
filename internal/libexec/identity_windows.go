//go:build windows

package libexec

import (
	"fmt"
	"os"
	"syscall"
)

// fileIdentity is what changes when a file's content does or it is replaced: its creation and
// last write times.
func fileIdentity(fi os.FileInfo) string {
	a, ok := fi.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return fi.ModTime().String()
	}

	return fmt.Sprintf("%d.%d %d.%d", a.CreationTime.HighDateTime, a.CreationTime.LowDateTime,
		a.LastWriteTime.HighDateTime, a.LastWriteTime.LowDateTime)
}
