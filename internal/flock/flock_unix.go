//go:build !windows

package flock

import (
	"errors"
	"fmt"
	"io/fs"
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

// TryAcquire takes the lock if nobody holds it. ok is false when somebody does, and
// then nothing is held and there is nothing to release.
//
// The same flock anchord takes on its control socket's .lock, so it answers for that
// file too: whether a daemon is serving there.
func TryAcquire(path string) (unlock func(), ok bool, err error) {
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

// Held reports whether somebody holds the lock on path, a file in a directory another
// account may write: anchor's lock beside a socket that anchord, running as its own
// account, made.
//
// So it is asked without trusting the file. It is opened to read and never created, and a
// symlink, a FIFO or a device is refused rather than opened, so the question cannot be
// turned into root creating, truncating or blocking on whatever the name was made to point
// at. A file that is not there is held by nobody.
func Held(path string) (bool, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
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

	switch err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); {
	case errors.Is(err, unix.EWOULDBLOCK):
		return true, nil
	case err != nil:
		return false, fmt.Errorf("lock %s: %w", path, err)
	}

	return false, nil
}
