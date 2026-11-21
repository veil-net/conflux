//go:build !windows

package flock

import (
	"os"
	"path/filepath"
	"strings"
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

// TestHeldInAsksThroughTheRootHeld: the serve lock tidy asks after before anything has judged the root
// is opened through the root held (paths' OpenIn): held while somebody holds it and free once they let
// go, where the root is this account's; nobody's where the root, or the lock, is not there; held through
// a link at the root's name to a directory of this account's own, holding a lock somebody holds, though
// every account may write that directory, which EnsureAll would narrow; and refused, naming the link,
// where the link leads nowhere, rather than taken for no lock.
func TestHeldInAsksThroughTheRootHeld(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	root := filepath.Join(base, "conflux")
	t.Setenv("CONFLUX_DIR", root)

	d := paths.Default()
	lock := d.ServeLockFile()

	if held, err := HeldIn(d, lock); held || err != nil {
		t.Errorf("HeldIn, no root there = %v, %v, want nobody's", held, err)
	}

	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	if held, err := HeldIn(d, lock); held || err != nil {
		t.Errorf("HeldIn, no lock there = %v, %v, want nobody's", held, err)
	}

	unlock, err := Acquire(lock)
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

	open := t.TempDir()

	theirs, err := Acquire(filepath.Join(open, "serve.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer theirs()

	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}

	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(open, root); err != nil {
		t.Fatal(err)
	}

	if held, err := HeldIn(d, lock); !held || err != nil {
		t.Errorf("HeldIn, the root a link to a directory of this account's own holding a held lock = %v, %v, want "+
			"it held", held, err)
	}

	if err := os.Remove(root); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(filepath.Join(base, "nowhere"), root); err != nil {
		t.Fatal(err)
	}

	if held, err := HeldIn(d, lock); err == nil || !strings.Contains(err.Error(), root+" is a link to ") {
		t.Errorf("HeldIn, the root a link to nothing = %v, %v, want a refusal naming the link", held, err)
	}
}
