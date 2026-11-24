package flock

import (
	"os"
	"path/filepath"
	"testing"
	"time"
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

// TestHeldAsksWithoutCreating: Held and HeldUntrusted alike say held while somebody holds the
// lock, free once they let go, and that a lock that is not there is nobody's -- and asking makes
// no file.
func TestHeldAsksWithoutCreating(t *testing.T) {
	for name, held := range map[string]func(string) (bool, error){"Held": Held, "HeldUntrusted": HeldUntrusted} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "x.lock")

			if held, err := held(path); err != nil || held {
				t.Fatalf("%s on a missing lock = %v, %v; want free", name, held, err)
			}

			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("%s, asking, made the lock file (%v)", name, err)
			}

			unlock, err := Acquire(path)
			if err != nil {
				t.Fatal(err)
			}

			if held, err := held(path); err != nil || !held {
				t.Errorf("%s on a held lock = %v, %v; want held", name, held, err)
			}

			unlock()

			if held, err := held(path); err != nil || held {
				t.Errorf("%s on a released lock = %v, %v; want free", name, held, err)
			}
		})
	}
}

// TestTryAcquireOutlastsAQuestion: a lock held for a moment -- Held asking whether anybody
// holds it, which takes it to find out -- is not mistaken for somebody running.
func TestTryAcquireOutlastsAQuestion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.lock")

	unlock, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}

	time.AfterFunc(15*time.Millisecond, unlock)

	release, ok, err := TryAcquire(path)
	if err != nil || !ok {
		t.Fatalf("TryAcquire beside a lock held a moment = ok %v, err %v; want it taken", ok, err)
	}

	release()
}
