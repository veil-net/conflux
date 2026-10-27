package flock

import (
	"os"
	"path/filepath"
	"testing"
)

// TestTryAcquireReportsAHeldLock: a lock somebody holds is reported held, with nothing
// taken, and is free again once they let go.
func TestTryAcquireReportsAHeldLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.lock")

	unlock, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}

	if _, ok, err := TryAcquire(path); err != nil || ok {
		t.Fatalf("TryAcquire on a held lock = ok %v, err %v; want held", ok, err)
	}

	unlock()

	again, ok, err := TryAcquire(path)
	if err != nil || !ok {
		t.Fatalf("TryAcquire on a released lock = ok %v, err %v; want it taken", ok, err)
	}

	again()
}

// TestHeldAsksWithoutCreating: held while somebody holds it, free once they let go, and a
// lock that is not there is nobody's -- and asking makes no file.
func TestHeldAsksWithoutCreating(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sock.lock")

	if held, err := Held(path); err != nil || held {
		t.Fatalf("Held on a missing lock = %v, %v; want free", held, err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("asking made the lock file (%v)", err)
	}

	unlock, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}

	if held, err := Held(path); err != nil || !held {
		t.Errorf("Held on a held lock = %v, %v; want held", held, err)
	}

	unlock()

	if held, err := Held(path); err != nil || held {
		t.Errorf("Held on a released lock = %v, %v; want free", held, err)
	}
}
