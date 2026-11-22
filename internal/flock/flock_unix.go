//go:build !windows

package flock

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// tryAcquire is one attempt at TryAcquire, and at AcquireContext: an exclusive advisory lock, taken
// at once or not at all. The returned function releases it and closes the file.
func tryAcquire(path string) (func(), bool, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false, fmt.Errorf("open the lock %s: %w", path, err)
	}

	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()

		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, false, nil
		}

		return nil, false, fmt.Errorf("lock %s: %w", path, err)
	}

	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
	}, true, nil
}

// plainLock is what openHeld refuses a lock for not being: a second name for another file --
// the supervisor's own serve.lock, held while it asks -- is not taken for anchord's.
const plainLock = "a regular file with one name"

// heldFile reports whether somebody holds the lock f, at path, holds open: whether it could be taken
// at once, let go of again where it was.
func heldFile(f *os.File, path string) (bool, error) {
	switch err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); {
	case errors.Is(err, unix.EWOULDBLOCK):
		return true, nil
	case err != nil:
		return false, fmt.Errorf("lock %s: %w", path, err)
	}

	return false, nil
}
