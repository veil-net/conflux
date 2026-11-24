//go:build !windows

package flock

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestHeldRefusesWhatIsNotALockFile: a lock is asked after without trusting the name -- the
// socket's lives where anchord's own account can write -- so a symlink is not followed, the
// file it names neither made nor locked, and a FIFO is refused rather than blocked on.
func TestHeldRefusesWhatIsNotALockFile(t *testing.T) {
	for name, held := range askers {
		dir := t.TempDir()

		target := filepath.Join(dir, "nologin")
		link := filepath.Join(dir, "link.lock")

		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}

		if _, err := held(link); err == nil {
			t.Errorf("%s asked through a symlinked lock", name)
		}

		if _, err := os.Lstat(target); !os.IsNotExist(err) {
			t.Errorf("%s, asking through a symlink, made %s (%v)", name, target, err)
		}

		fifo := filepath.Join(dir, "fifo.lock")
		if err := syscall.Mkfifo(fifo, 0o600); err != nil {
			t.Fatal(err)
		}

		done := make(chan error, 1)

		go func() {
			_, err := held(fifo)
			done <- err
		}()

		select {
		case err := <-done:
			if err == nil {
				t.Errorf("%s took a FIFO for a lock", name)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s, asking about a FIFO, blocked", name)
		}
	}
}

// TestHeldUntrustedRefusesALockWithASecondName: anchord's account can hard-link a file of root's
// into its own directory -- the supervisor's serve.lock, which root holds for as long as it
// serves -- under the name of its socket's lock. Asked there, the answer would be root's lock,
// and on OpenBSD the orphan reap takes that answer for anchord serving the socket. So a lock
// asked after where the account writes is refused, by either name, when it has a second name;
// one asked for by its own name, where the account does not write, is still answered.
func TestHeldUntrustedRefusesALockWithASecondName(t *testing.T) {
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
		if held, err := HeldUntrusted(path); err == nil {
			t.Errorf("HeldUntrusted(%s), a lock with a second name, = %v, nil; want it refused", filepath.Base(path), held)
		}
	}

	if held, err := Held(serve); err != nil || !held {
		t.Errorf("Held(serve.lock), held and given a second name, = %v, %v; want held", held, err)
	}
}
