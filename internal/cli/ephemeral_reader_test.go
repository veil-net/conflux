package cli

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/flock"
	"github.com/veil-net/conflux/internal/libexec"
	"github.com/veil-net/conflux/internal/paths"
)

// startingEphemeral is an ephemeral root as a run that has just taken its lock finds it
// after another was killed: the lock held, the killed run's socket still there, and its
// extracted binaries half cleared away.
func startingEphemeral(t *testing.T) paths.Dirs {
	t.Helper()

	t.Setenv("CONFLUX_DIR", t.TempDir())

	d := paths.EphemeralDirs(paths.EphemeralCandidates()[0])
	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	unlock, ok, err := flock.TryAcquire(d.ServeLockFile())
	if err != nil || !ok {
		t.Fatalf("hold the run's lock: %v", err)
	}

	t.Cleanup(unlock)

	if err := os.MkdirAll(filepath.Dir(d.Socket()), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(d.Socket(), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	return d
}

// TestStatusWritesNothingIntoAStartingEphemeralRun: status, asked while an ephemeral run is
// clearing what a killed one left, neither extracts binaries into the run's root nor asks
// its daemon. Extracting there is what raced the run's own clearing, which then found the
// directory it was emptying refilled.
func TestStatusWritesNothingIntoAStartingEphemeralRun(t *testing.T) {
	anchortest.Require(t)

	d := startingEphemeral(t)

	if _, live := liveEphemeral(); !live {
		t.Fatal("the starting run is not seen as live")
	}

	capture(t, "status")

	if entries, err := os.ReadDir(d.Libexec()); err == nil && len(entries) > 0 {
		t.Errorf("status wrote %d entries into the run's %s", len(entries), d.Libexec())
	}
}

// TestAReaderTakesAnEphemeralRunsPairAsItIs: before the run marks itself up, a reader is
// told it is starting; after, it gets the pair the run extracted, and where the run has
// none it is told so -- in neither case writing anything into the run's root.
func TestAReaderTakesAnEphemeralRunsPairAsItIs(t *testing.T) {
	anchortest.Require(t)

	d := startingEphemeral(t)

	if _, err := toolsFor(d); !errors.Is(err, errEphemeralStarting) {
		t.Errorf("before the run is up: %v, want errEphemeralStarting", err)
	}

	if err := daemon.MarkReady(d, "anchorx"); err != nil {
		t.Fatal(err)
	}

	if _, err := toolsFor(d); !errors.Is(err, libexec.ErrNotExtracted) {
		t.Errorf("a run with no pair: %v, want ErrNotExtracted", err)
	}

	if entries, _ := os.ReadDir(d.Libexec()); len(entries) > 0 {
		t.Errorf("a reader wrote %d entries into the run's %s", len(entries), d.Libexec())
	}

	extracted, err := libexec.Ensure(d) // as the run does
	if err != nil {
		t.Fatal(err)
	}

	got, err := toolsFor(d)
	if err != nil || got.Anchorctl != extracted.Anchorctl {
		t.Errorf("a run that is up: %+v, %v; want %s", got, err, extracted.Anchorctl)
	}

	// An installed root is the reader's own to extract into, as it always was.
	t.Setenv("CONFLUX_DIR", t.TempDir())

	if _, err := toolsFor(paths.Default()); err != nil {
		t.Errorf("an installed root: %v", err)
	}
}
