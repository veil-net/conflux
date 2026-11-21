//go:build windows

package flock

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"golang.org/x/sys/windows"

	"github.com/veil-net/conflux/internal/paths"
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
	f, err := openLock(path)
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

// openLock opens the lock at path to read and write, made where it is not there yet and given then
// to the Administrators (paths.Own), as everything conflux makes in a root is: what an elevated
// administrator makes is that administrator's on a Windows client, and the SYSTEM service refuses
// a root holding it.
func openLock(path string) (*os.File, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if !errors.Is(err, fs.ErrNotExist) {
		return f, err
	}

	switch f, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600); {
	case errors.Is(err, fs.ErrExist):
		return os.OpenFile(path, os.O_RDWR, 0) // made meanwhile, by whoever holds it
	case err != nil:
		return nil, err
	}

	if err := paths.Own(path); err != nil {
		f.Close()

		return nil, err
	}

	return f, nil
}

// plainLock is what openHeld refuses a lock for not being: a reparse point, opened as itself,
// is not one.
const plainLock = "a regular file"

// Held reports whether somebody holds the lock on path, a file in a directory anchord's
// own account may write. It is opened without trusting the file (openHeld), so asking cannot
// be turned into SYSTEM creating a file wherever the name was made to lead, or locking it. A
// file that is not there is held by nobody.
func Held(path string) (bool, error) {
	f, err := openHeld(path)
	if f == nil {
		return false, err
	}
	defer f.Close()

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
