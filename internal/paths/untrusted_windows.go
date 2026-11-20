package paths

import (
	"os"

	"golang.org/x/sys/windows"
)

// OpenUntrusted is how a file in a directory another account can write is opened, by name
// or within an os.Root: to read, and a reparse point -- a symbolic link, a junction -- as
// itself rather than whatever it leads to, which PlainFile then refuses.
const OpenUntrusted = os.O_RDONLY | windows.FILE_FLAG_OPEN_REPARSE_POINT

// PlainFile reports whether fi, of a file opened with OpenUntrusted, is one to use: a
// regular file, which a reparse point opened as itself is not, of no more than max bytes.
// Its links are not counted: linking to a file on Windows takes the right to write it.
func PlainFile(fi os.FileInfo, max int64) bool {
	return fi.Mode().IsRegular() && fi.Size() <= max
}
