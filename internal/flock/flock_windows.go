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
