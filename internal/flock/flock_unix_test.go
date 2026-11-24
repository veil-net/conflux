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

// TestHeldRefusesALockWithASecondName: anchord's account can hard-link a file of root's into
// its own directory -- the supervisor's serve.lock, which root holds for as long as it serves --
// under the name of its socket's lock. Asked there, the answer would be root's lock, and on
// OpenBSD the orphan reap takes that answer for anchord serving the socket. A lock file with a
// second name is refused, by either name, rather than reported held.
func TestHeldRefusesALockWithASecondName(t *testing.T) {
	dir := t.TempDir()

	serve := filepath.Join(dir, "serve.lock")

	unlock, err := Acquire(serve)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()

	link := filepath.Join(dir, "sock.lock")
	if err := os.Link(serve, link); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{link, serve} {
		if held, err := Held(path); err == nil {
			t.Errorf("Held(%s), a lock with a second name, = %v, nil; want it refused", filepath.Base(path), held)
		}
	}
}
