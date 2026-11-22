package flock

import (
	"context"
	"errors"
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
// here is 25 ms, past what three tries span, so a TryAcquire that gave up after three or
// fewer would fail.
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

// TestAcquireContextWaitsUntilToldNotTo: a held lock is waited for, the caller told once, after a second,
// that it waits, and taken once its holder lets go; and a wait whose context ends -- Ctrl+C -- ends then,
// with the context's error and nothing held, the lock still its holder's.
func TestAcquireContextWaitsUntilToldNotTo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.lock")

	unlock, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}

	var told atomic.Int32

	time.AfterFunc(1500*time.Millisecond, unlock)

	start := time.Now()

	release, err := AcquireContext(t.Context(), path, func() { told.Add(1) })
	if err != nil {
		t.Fatalf("AcquireContext on a lock let go of after 1.5 s = %v", err)
	}

	if took := time.Since(start); took < time.Second || told.Load() != 1 {
		t.Errorf("AcquireContext took the lock after %v, saying it waited %d times; want after its holder let go, "+
			"once", took, told.Load())
	}

	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()

	if _, err := AcquireContext(ctx, path, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("AcquireContext on a held lock, its context ended = %v, want the context's error", err)
	}

	release()
}
