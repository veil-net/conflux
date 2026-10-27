//go:build windows

package flock

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"golang.org/x/sys/windows"
)

// Acquire takes an exclusive lock on the whole file, blocking until it is ours.
//
// The returned function releases it and closes the file.
func Acquire(path string) (func(), error) {
	unlock, _, err := lock(path, windows.LOCKFILE_EXCLUSIVE_LOCK)

	return unlock, err
}

// TryAcquire takes the lock if nobody holds it. ok is false when somebody does, and
// then nothing is held and there is nothing to release.
//
// The same lock anchord takes on its control socket's .lock, so it answers for that
// file too: whether a daemon is serving there.
func TryAcquire(path string) (unlock func(), ok bool, err error) {
	unlock, ok, err = lock(path, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY)
	if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
		return nil, false, nil
	}

	return unlock, ok, err
}

func lock(path string, flags uint32) (func(), bool, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false, fmt.Errorf("open the lock %s: %w", path, err)
	}

	h := windows.Handle(f.Fd())
	ol := new(windows.Overlapped)

	if err := windows.LockFileEx(h, flags, 0, 1, 0, ol); err != nil {
		f.Close()

		return nil, false, fmt.Errorf("lock %s: %w", path, err)
	}

	return func() {
		_ = windows.UnlockFileEx(h, 0, 1, 0, ol)
		f.Close()
	}, true, nil
}

// Held reports whether somebody holds the lock on path, a file in a directory anchord's
// own account may write. It is opened to read and never created, and anything but a
// regular file is refused, so asking cannot be turned into SYSTEM creating a file
// wherever the name was made to lead. A file that is not there is held by nobody.
func Held(path string) (bool, error) {
	f, err := os.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("open the lock %s: %w", path, err)
	}
	defer f.Close()

	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return false, fmt.Errorf("the lock %s is not a regular file", path)
	}

	h := windows.Handle(f.Fd())
	ol := new(windows.Overlapped)

	switch err := windows.LockFileEx(h, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol); {
	case errors.Is(err, windows.ERROR_LOCK_VIOLATION):
		return true, nil
	case err != nil:
		return false, fmt.Errorf("lock %s: %w", path, err)
	}

	_ = windows.UnlockFileEx(h, 0, 1, 0, ol)

	return false, nil
}
