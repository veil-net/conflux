//go:build windows

package flock

import (
	"errors"
	"fmt"
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

// tryAcquire is one attempt at TryAcquire.
func tryAcquire(path string) (unlock func(), ok bool, err error) {
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

// plainLock is what openHeld refuses a lock for not being: a reparse point, opened as itself,
// is not one.
const plainLock = "a regular file"

// heldFile reports whether somebody holds the lock f, at path, holds open: whether it could be taken
// at once, let go of again where it was.
func heldFile(f *os.File, path string) (bool, error) {
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
