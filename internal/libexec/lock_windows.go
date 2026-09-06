//go:build windows

package libexec

import (
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// lock takes an exclusive lock on the whole file, blocking until it is ours.
func lock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open the extraction lock %s: %w", path, err)
	}

	h := windows.Handle(f.Fd())
	ol := new(windows.Overlapped)

	if err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, ol); err != nil {
		f.Close()

		return nil, fmt.Errorf("lock %s: %w", path, err)
	}

	return func() {
		_ = windows.UnlockFileEx(h, 0, 1, 0, ol)
		f.Close()
	}, nil
}
