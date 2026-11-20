// Package flock takes exclusive advisory locks on files.
//
// libexec serialises the extraction of the embedded anchor pair with one, and the
// daemon everything that rewrites the manifest and the state -- a bring-up, a renewal,
// the uplink watcher's count, `conflux enrol` -- with another. A third keeps one
// supervisor per root, and Held on anchord's own socket lock says whether a daemon is
// serving there. The primitive is three lines of platform
// code either way, which is exactly the size of thing that gets copied rather than
// shared and then diverges on the platform nobody develops on.
package flock

import (
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"time"

	"github.com/veil-net/conflux/internal/paths"
)

// TryAcquire takes the lock if nobody holds it. ok is false when somebody does, and then
// nothing is held and there is nothing to release.
//
// Asked again for a moment before it says somebody does. Held takes the lock for an instant
// to learn whether anybody else has it, and a run starting at that instant -- an ephemeral
// one, while `conflux status` asks after its root -- would otherwise refuse itself as already
// running. A holder that is there stays there; a question is gone in microseconds.
//
// Not for anchord's socket lock, whose directory anchord's account may write: this opens
// with O_CREATE, and Held is the way to ask after that one.
func TryAcquire(path string) (unlock func(), ok bool, err error) {
	for tries := 1; ; tries++ {
		unlock, ok, err = tryAcquire(path)
		if ok || err != nil || tries == 5 {
			return unlock, ok, err
		}

		time.Sleep(10 * time.Millisecond)
	}
}

// openHeld opens the lock at path for Held, without trusting it: to read and never created, as
// paths.OpenUntrusted opens a file -- never through a symlink or, on Windows, a reparse point,
// never blocking on a FIFO -- and kept only where it is plainLock. Neither file nor error where
// there is no file at all.
func openHeld(path string) (*os.File, error) {
	f, err := os.OpenFile(path, paths.OpenUntrusted, 0)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}

	if err != nil {
		return nil, fmt.Errorf("open the lock %s: %w", path, err)
	}

	if fi, err := f.Stat(); err != nil || !paths.PlainFile(fi, math.MaxInt64) {
		f.Close()

		return nil, fmt.Errorf("the lock %s is not %s", path, plainLock)
	}

	return f, nil
}
