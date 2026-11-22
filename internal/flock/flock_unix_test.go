//go:build !windows

package flock

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/paths"
)

// TestHeldRefusesWhatIsNotALockFile: the lock lives where anchord's own account can write,
// so a symlink there is not followed -- the file it names is neither made nor locked -- a
// FIFO is refused rather than blocked on, and a second name for another file, which the
// account can make for any file it can name -- the supervisor's own serve.lock, held while
// it asks -- is refused rather than taken for anchord's.
func TestHeldRefusesWhatIsNotALockFile(t *testing.T) {
	dir := t.TempDir()

	serve := filepath.Join(t.TempDir(), "serve.lock")
	if err := os.WriteFile(serve, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	hard := filepath.Join(dir, "hard.lock")
	if err := os.Link(serve, hard); err != nil {
		t.Fatal(err)
	}

	if _, err := Held(hard); err == nil {
		t.Error("a second name for another file was asked about as a lock")
	}

	target := filepath.Join(dir, "nologin")
	link := filepath.Join(dir, "link.lock")

	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if _, err := Held(link); err == nil {
		t.Error("a symlinked lock was asked through")
	}

	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Errorf("asking through a symlink made %s (%v)", target, err)
	}

	fifo := filepath.Join(dir, "fifo.lock")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)

	go func() {
		_, err := Held(fifo)
		done <- err
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Error("a FIFO was taken for a lock")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("asking about a FIFO blocked")
	}
}

// TestHeldInAsksThroughTheRootHeld: the serve lock tidy asks after before anything has made the root is
// opened through the root held (paths' OpenIn): held while somebody holds it and free once they let go,
// where the root is this account's; nobody's where the root, or the lock, is not there; and nobody's
// where a link is at the root's name, which is no root of conflux's, whatever it leads to -- here a
// directory of this account's own holding a lock somebody holds, and nothing.
func TestHeldInAsksThroughTheRootHeld(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONFLUX_DIR", filepath.Join(base, "conflux"))

	d := paths.Default()
	root, lock := d.State, d.ServeLockFile()

	if held, err := HeldIn(d, lock); held || err != nil {
		t.Errorf("HeldIn, no root there = %v, %v, want nobody's", held, err)
	}

	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	if held, err := HeldIn(d, lock); held || err != nil {
		t.Errorf("HeldIn, no lock there = %v, %v, want nobody's", held, err)
	}

	unlock, err := AcquireContext(t.Context(), lock, nil)
	if err != nil {
		t.Fatal(err)
	}

	if held, err := HeldIn(d, lock); !held || err != nil {
		t.Errorf("HeldIn, the lock held = %v, %v, want it held", held, err)
	}

	unlock()

	if held, err := HeldIn(d, lock); held || err != nil {
		t.Errorf("HeldIn, the lock let go of = %v, %v, want nobody's", held, err)
	}

	elsewhere := t.TempDir()

	theirs, err := AcquireContext(t.Context(), filepath.Join(elsewhere, "serve.lock"), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer theirs()

	for _, target := range []string{elsewhere, filepath.Join(base, "nowhere")} {
		if err := os.RemoveAll(root); err != nil {
			t.Fatal(err)
		}

		if err := os.Symlink(target, root); err != nil {
			t.Fatal(err)
		}

		if held, err := HeldIn(d, lock); held || err != nil {
			t.Errorf("HeldIn, the root a link to %s = %v, %v, want nobody's", target, held, err)
		}
	}
}
