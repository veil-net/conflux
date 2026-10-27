//go:build !windows

package flock

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestHeldRefusesWhatIsNotALockFile: the lock lives where anchord's own account can write,
// so a symlink there is not followed -- the file it names is neither made nor locked -- and
// a FIFO is refused rather than blocked on.
func TestHeldRefusesWhatIsNotALockFile(t *testing.T) {
	dir := t.TempDir()

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
