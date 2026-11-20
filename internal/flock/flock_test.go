package flock

import (
	"os"
	"path/filepath"
	"sync/atomic"
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

// TestTryAcquireOutlastsAQuestion: a lock held for a moment -- Held asking whether anybody
// holds it, which takes it to find out -- is not mistaken for somebody running. The moment
// here is 25 ms, past what two or three tries span, so a TryAcquire that gave up sooner
// than its five would fail.
//
// The moment ends on a timer, which a loaded runner under -race can fire after every try is
// spent; a round like that shows nothing either way, and is run again. The failure is a
// lock freed before the last try that TryAcquire still gave up on.
func TestTryAcquireOutlastsAQuestion(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.lock")

	for round := 1; ; round++ {
		unlock, err := Acquire(path)
		if err != nil {
			t.Fatal(err)
		}

		var freedAt atomic.Int64

		freed := make(chan struct{})

		time.AfterFunc(25*time.Millisecond, func() {
			unlock()
			freedAt.Store(time.Now().UnixNano())
			close(freed)
		})

		release, ok, err := TryAcquire(path)
		returned := time.Now()

		if err != nil {
			t.Fatal(err)
		}

		<-freed

		if ok {
			release()

			return
		}

		if early := returned.Sub(time.Unix(0, freedAt.Load())); early > time.Millisecond {
			t.Fatalf("TryAcquire gave up on a lock freed %v before it answered", early)
		}

		if round == 20 {
			t.Fatalf("in %d rounds the moment outlasted every try TryAcquire makes", round)
		}
	}
}
