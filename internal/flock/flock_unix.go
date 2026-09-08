//go:build !windows

package libexec

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// lock takes an exclusive advisory lock, blocking until it is ours.
//
// Blocking rather than failing: the contended case is two conflux processes at boot
// -- the unit and an impatient operator -- and the right behaviour there is for the
// second to wait a moment and then find the work already done.
func lock(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open the extraction lock %s: %w", path, err)
	}

	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()

		return nil, fmt.Errorf("lock %s: %w", path, err)
	}

	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		f.Close()
	}, nil
}
