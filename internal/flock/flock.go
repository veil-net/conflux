// Package flock takes exclusive advisory locks on files.
//
// libexec serialises the extraction of the embedded anchor pair with one, and the daemon
// everything that rewrites the manifest and the state -- a bring-up, a renewal, the
// uplink watcher's count, `conflux enrol` -- with another, each waited for until the
// caller stops waiting (AcquireContext). A third keeps one
// supervisor per root, and Held on anchord's own socket lock says whether a daemon is
// serving there. The primitive is three lines of platform
// code either way, which is exactly the size of thing that gets copied rather than
// shared and then diverges on the platform nobody develops on.
package flock

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"os"
	"runtime"
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

// AcquireContext takes an exclusive lock on path, waiting for whoever holds it until ctx ends, and is what
// releases it and closes the file. It asks again every 10 ms rather than block, so a lock let go of is
// taken within that, and a wait ctx ends -- Ctrl+C, the service stopping -- ends at once, with its error.
// Waiting rather than failing: the contended case is two conflux processes at once -- the service and
// an operator -- and the second should wait a moment and then find the work done. waiting, where it is
// not nil, is called once, after a second, where the lock is still held, for the caller to say what it
// waits for.
func AcquireContext(ctx context.Context, path string, waiting func()) (func(), error) {
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()

	say := time.Now().Add(time.Second)

	for {
		unlock, ok, err := tryAcquire(path)
		if ok || err != nil {
			return unlock, err
		}

		if waiting != nil && time.Now().After(say) {
			waiting()
			waiting = nil
		}

		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("stopped waiting for the lock %s: %w", path, context.Cause(ctx))
		case <-tick.C:
		}
	}
}

// Held reports whether somebody holds the lock on path, a file in a directory another account may
// write: anchor's lock beside a socket that anchord, running as its own account, made. It is opened
// without trusting the file (openHeld), by its name, so the question cannot be turned into root
// (SYSTEM) creating, truncating, locking or blocking on whatever the name was made to point at. A file
// that is not there is held by nobody.
func Held(path string) (bool, error) {
	return held(path, func() (*os.File, error) { return os.OpenFile(path, paths.OpenUntrusted, 0) })
}

// HeldIn is Held for the lock at path, a file directly in d's root, asked before anything has
// made the root -- the serve lock, before conflux decides to stop the service: opened through the root
// held as paths' OpenIn holds it, judged as a reader judges it, and a link at its name never followed,
// so that a root another account made -- on Windows %ProgramData% lets any account make one first --
// cannot answer with a lock of theirs. A root or a lock that is not there, or a root not as conflux
// makes one, is held by nobody; anything else OpenIn refuses is refused.
func HeldIn(d paths.Dirs, path string) (bool, error) {
	return held(path, func() (*os.File, error) { return d.OpenIn(path) })
}

// Drop removes the lock file at path, which nothing holds now, where the system removes no file
// anybody has open (Windows), so whatever takes it next makes it again; and says whether it did. On
// Unix it is kept: a lock is taken on the file its name led to when it was opened, so one waited for
// on a file removed meanwhile would be held beside one taken on the file made again at its name.
func Drop(path string) bool {
	return runtime.GOOS == "windows" && os.Remove(path) == nil
}

// held is whether somebody holds the lock at path, opened by open (openHeld): nobody, where there is
// no file at all.
func held(path string, open func() (*os.File, error)) (bool, error) {
	f, err := openHeld(path, open)
	if f == nil {
		return false, err
	}
	defer f.Close()

	return heldFile(f, path)
}

// openHeld opens the lock at path through open, without trusting it: to read and never created, as
// paths.OpenUntrusted opens a file -- never through a symlink or, on Windows, a reparse point, never
// blocking on a FIFO -- and kept only where it is plainLock. Neither file nor error where there is no
// file at all.
func openHeld(path string, open func() (*os.File, error)) (*os.File, error) {
	f, err := open()
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
