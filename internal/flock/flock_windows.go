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

// Held reports whether somebody holds the lock on path, asked for by its own name: an
// ephemeral run's serve.lock, which status, pass-through and uninstall ask after. It is
// opened to read and never created, and anything but a regular file is refused, so asking
// cannot be turned into SYSTEM creating a file wherever the name was made to lead. A file
// that is not there is held by nobody.
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

// HeldUntrusted is Held for a lock in a directory anchord's own account may write: anchor's
// lock beside its socket. It asks nothing more than Held does. The second name Unix refuses is
// not asked after: linking a file on Windows takes write access to it, so one the account made
// is of a lock it could write already, never of SYSTEM's.
func HeldUntrusted(path string) (bool, error) { return Held(path) }
