package config

import (
	"os"
	"syscall"

	"golang.org/x/sys/windows"
)

// OpenUntrusted is how a file in a directory another account can write is opened: the name
// itself, never what a symbolic link or a junction of that name points at.
const OpenUntrusted = os.O_RDONLY | windows.O_FILE_FLAG_OPEN_REPARSE_POINT

// Untrusted reports whether fi, the file a name opened with OpenUntrusted, is one conflux
// reads: a regular file, no reparse point of any kind, and no more than max bytes.
//
// A FileInfo carries no link count here. ReadUntrusted asks the handle for it (oneName);
// copying between anchord's two directories (the daemon's copyTree) does not, since linking a
// file on Windows takes write access to it, so a second name the account made is of a file it
// could write already.
func Untrusted(fi os.FileInfo, max int64) bool {
	attrs, ok := fi.Sys().(*syscall.Win32FileAttributeData)

	return fi.Mode().IsRegular() && ok && attrs.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 &&
		fi.Size() <= max
}

// oneName reports whether f has no second name, from its handle.
func oneName(f *os.File) bool {
	var info windows.ByHandleFileInformation

	return windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &info) == nil && info.NumberOfLinks == 1
}
