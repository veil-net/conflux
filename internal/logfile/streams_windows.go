package logfile

import (
	"os"

	"golang.org/x/sys/windows"
)

// placed is the handle the standard streams were last given: a copy of the log's, so that
// closing the log at a move aside leaves them a handle that is still the log's.
var placed windows.Handle

// standardStreams makes f the process's standard output and error. A service has none of
// its own, and the runtime asks Windows for them at every write it makes itself -- a panic
// among them -- so what it writes lands in the log, as dup2 makes it on Unix. The copy
// given before is closed once the streams no longer name it. Called under the File's lock,
// or before anything shares it.
func standardStreams(f *os.File) {
	self := windows.CurrentProcess()

	var h windows.Handle
	if err := windows.DuplicateHandle(self, windows.Handle(f.Fd()), self, &h, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return
	}

	_ = windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, h)
	_ = windows.SetStdHandle(windows.STD_ERROR_HANDLE, h)

	if placed != 0 {
		_ = windows.CloseHandle(placed)
	}

	placed = h
}
