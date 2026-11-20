//go:build !windows

package flock

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Acquire takes an exclusive advisory lock, blocking until it is ours.
//
// The returned function releases it and closes the file.
//
// Blocking rather than failing: the contended case is two conflux processes at boot
// -- the unit and an impatient operator -- and the right behaviour there is for the
// second to wait a moment and then find the work already done.
func Acquire(path string) (func(), error) {
	unlock, _, err := lock(path, unix.LOCK_EX)

	return unlock, err
}

// tryAcquire is one attempt at TryAcquire.
func tryAcquire(path string) (unlock func(), ok bool, err error) {
	unlock, ok, err = lock(path, unix.LOCK_EX|unix.LOCK_NB)
	if errors.Is(err, unix.EWOULDBLOCK) {
		return nil, false, nil
	}

	return unlock, ok, err
}

func lock(path string, how int) (func(), bool, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false, fmt.Errorf("open the lock %s: %w", path, err)
	}

	if err := unix.Flock(int(f.Fd()), how); err != nil {
		f.Close()

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

// Held reports whether somebody holds the lock on path, a file in a directory another
// account may write: anchor's lock beside a socket that anchord, running as its own
// account, made. It is opened without trusting the file (openHeld), so the question cannot
// be turned into root creating, truncating or blocking on whatever the name was made to
// point at. A file that is not there is held by nobody.
func Held(path string) (bool, error) {
	f, err := openHeld(path)
	if f == nil {
		return false, err
	}
	defer f.Close()

	switch err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); {
	case errors.Is(err, unix.EWOULDBLOCK):
		return true, nil
	case err != nil:
		return false, fmt.Errorf("lock %s: %w", path, err)
	}

	return false, nil
}
