//go:build !windows

package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/anchorctl"
	"github.com/veil-net/conflux/internal/config"
)

// TestAStopDuringTheObserversStartIsNoFailure: a stop that comes while the observer is being
// started is no failure of the start, as one that cuts an anchor's start or rebuild short is not
// (TestAStopThatEndsABringUpIsNoFailure). Beside an anchor, the cycle's start warns of nothing and
// goes no further -- no anchor directory made, no anchor started -- and hands back a failure the
// stopped cycle drops. The state is written all the same, naming the pair, as after any failure
// once the credential is had, which keeps what the credential came to. The watcher's restart of an
// observer whose capture ended says that much and nothing more, charges nothing to the
// observer's keeper, and does not give the observer up. Unix's alone, for the FIFO.
func TestAStopDuringTheObserversStartIsNoFailure(t *testing.T) {
	cfg := &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}, Observer: &config.Observer{}}

	t.Run("the start", func(t *testing.T) {
		s, log := supervised(t, "1")
		credentialed(t, s.Dirs)
		s.priv.Dir = s.Dirs.RootAnchorDir()
		s.ctl.SetID = "the set"

		w := &warnings{}
		s.Reporter = w

		if err := config.Save(s.Dirs, cfg); err != nil {
			t.Fatal(err)
		}

		var (
			id             string
			anchorErr, err error
		)

		stoppedDuringTheObserversStart(t, log, func(ctx context.Context) { id, anchorErr, err = s.up(ctx, cfg) })

		if id != "" || anchorErr != nil || err == nil {
			t.Errorf("the start, stopped, = %q, %v, %v; want its failure alone, which the stopped cycle drops",
				id, anchorErr, err)
		}

		if len(w.said) > 0 {
			t.Errorf("the start, stopped, warned %q", w.said)
		}

		if _, err := os.Stat(s.Dirs.RootAnchorDir()); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the start, stopped, went on to make the anchor's directory (%v)", err)
		}

		if cmds := ran(t, log); !slices.Equal(cmds, []string{"observe"}) {
			t.Errorf("anchorctl ran %v; want the observer's start alone", cmds)
		}

		if st, err := config.LoadState(s.Dirs); err != nil {
			t.Error(err)
		} else if st.BinSetID != s.ctl.SetID {
			t.Errorf("the start, stopped, left a state naming the pair %q; want it written, naming %q",
				st.BinSetID, s.ctl.SetID)
		}
	})

	t.Run("the watcher's restart", func(t *testing.T) {
		s, log := supervised(t, "1")
		credentialed(t, s.Dirs)

		w := &warnings{}
		s.Reporter = w

		k := newKeeper()

		var gaveUp bool

		stoppedDuringTheObserversStart(t, log, func(ctx context.Context) {
			gaveUp = s.restartObserver(ctx, cfg, anchorctl.Observer{Note: "not observing: capture ended"}, k)
		})

		if gaveUp {
			t.Error("the restart, stopped, gave the observer up")
		}

		if want := []string{"the observer stopped (capture ended); starting it again"}; !slices.Equal(w.said, want) {
			t.Errorf("the restart, stopped, warned %q; want %q alone", w.said, want)
		}

		if *k != *newKeeper() {
			t.Errorf("the restart, stopped, was charged to the observer: backoff %v, %d refusals, not before %v",
				k.backoff, k.refusals, k.notBefore)
		}
	})
}

// stoppedDuringTheObserversStart runs bring under a context cancelled once the stand-in
// anchorctl has begun `observe -start`, which it does not finish while it runs: it blocks
// writing the manifest it was handed into a FIFO nobody reads. It returns once bring has.
func stoppedDuringTheObserversStart(t *testing.T, log string, bring func(context.Context)) {
	t.Helper()

	fifo := filepath.Join(t.TempDir(), "observed")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv(fakeAnchorctlObservedEnv, fifo)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	done := make(chan struct{})

	go func() {
		defer close(done)

		bring(ctx)
	}()

	eventually(t, "the observer's start", func() bool { return slices.Contains(ran(t, log), "observe") })
	cancel()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("it did not return once stopped")
	}
}
