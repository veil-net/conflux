//go:build !windows

package flock

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"golang.org/x/sys/unix"

	"github.com/veil-net/conflux/internal/config"
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

// lockMax bounds a lock file Held asks after. Neither anchord nor the supervisor writes
// anything in its lock; config.Untrusted takes a bound, and a page is more than any lock holds.
const lockMax = 4 << 10

// Held reports whether somebody holds the lock on path, a file in a directory another
// account may write: anchor's lock beside a socket that anchord, running as its own
// account, made.
//
// So it is asked without trusting the file. It is opened as every such file is
// (config.OpenUntrusted), to read and never created, and a symlink, a FIFO or a device is
// refused rather than opened, so the question cannot be turned into root creating,
// truncating or blocking on whatever the name was made to point at. And it is held to what
// such a file must be (config.Untrusted): a regular file with one name. A second name is a
// hard link the account may have made to a lock of root's -- the supervisor's serve.lock,
// held for as long as it serves -- whose answer would be root's, and which on OpenBSD the
// orphan reap would take for anchord serving the socket; so it is refused, not asked
// about. A file that is not there is held by nobody.
func Held(path string) (bool, error) {
	f, err := os.OpenFile(path, config.OpenUntrusted, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}

	if err != nil {
		return false, fmt.Errorf("open the lock %s: %w", path, err)
	}
	defer f.Close()

	if fi, err := f.Stat(); err != nil || !config.Untrusted(fi, lockMax) {
		return false, fmt.Errorf("the lock %s is not a regular file with one name", path)
	}

	switch err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); {
	case errors.Is(err, unix.EWOULDBLOCK):
		return true, nil
	case err != nil:
		return false, fmt.Errorf("lock %s: %w", path, err)
	}

	return false, nil
}
