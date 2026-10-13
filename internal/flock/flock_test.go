package flock

import (
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
