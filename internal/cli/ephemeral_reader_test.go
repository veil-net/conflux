package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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

	t.Cleanup(paths.UseRoot(t.TempDir()))

	d := paths.Ephemeral()
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

// TestEphemeralAtSeesARunWhoseLockHasASecondName: anchord's account writes run/anchord/ and
// can hard-link the run's serve.lock into it, as anchor's socket lock. Asked for by its own
// name, in a root the account does not write, the lock still says whether the run is live or
// was killed: a second name is no reason to read the root as holding no run, which would let
// uninstall pass a live run by, and leave a killed one's root behind.
func TestEphemeralAtSeesARunWhoseLockHasASecondName(t *testing.T) {
	root := t.TempDir()
	d := paths.Dirs{Root: root}

	unlock, err := flock.Acquire(d.ServeLockFile())
	if err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(d.DaemonRun(), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.Link(d.ServeLockFile(), d.Socket()+".lock"); err != nil {
		t.Fatal(err)
	}

	if _, run := ephemeralAt(root); run != liveRun {
		t.Errorf("a live run whose lock has a second name: %v, want liveRun (%v)", run, liveRun)
	}

	unlock()

	if _, run := ephemeralAt(root); run != staleRun {
		t.Errorf("a killed run whose lock has a second name: %v, want staleRun (%v)", run, staleRun)
	}
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

// TestAKilledRunsMarkerIsNotTheNextRuns: a run killed outright leaves its readiness marker
// in the root, and the next run, holding the lock, takes a moment to clear it. Read beside
// that lock, the old marker said the new run was up -- status reported it running, then
// starting once the root was cleared, then running -- and let a reader into a root being
// emptied. Neither status nor a reader takes it for the new run's.
func TestAKilledRunsMarkerIsNotTheNextRuns(t *testing.T) {
	anchortest.Require(t)

	d := startingEphemeral(t)

	killed := exec.Command(os.Args[0], "-test.run=^$")
	if err := killed.Run(); err != nil {
		t.Fatalf("run a process to end: %v", err)
	}

	marker := fmt.Sprintf("%s anchorkilled %d\n", time.Now().UTC().Format(time.RFC3339Nano), killed.ProcessState.Pid())
	if err := os.WriteFile(d.ReadyFile(), []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := toolsFor(d); !errors.Is(err, errEphemeralStarting) {
		t.Errorf("a reader, with the killed run's marker beside the new run's lock: %v, want errEphemeralStarting", err)
	}

	if out, _, _ := capture(t, "status"); !strings.Contains(out, "starting, from "+d.Root) {
		t.Errorf("status, with the killed run's marker beside the new run's lock, does not say it is starting:\n%s", out)
	}
}

// TestAReaderTakesAnEphemeralRunsPairAsItIs: before the run marks itself up, a reader is
// told it is starting; after, on Linux it runs its own anchorctl from memory, as the run
// does, and elsewhere it gets the pair the run extracted, and where the run has none it is
// told so -- in no case writing anything into the run's root.
func TestAReaderTakesAnEphemeralRunsPairAsItIs(t *testing.T) {
	anchortest.Require(t)

	d := startingEphemeral(t)

	if _, err := toolsFor(d); !errors.Is(err, errEphemeralStarting) {
		t.Errorf("before the run is up: %v, want errEphemeralStarting", err)
	}

	if err := daemon.MarkReady(d, "anchorx"); err != nil {
		t.Fatal(err)
	}

	got, err := toolsFor(d)
	if runtime.GOOS == "linux" {
		if err != nil || !strings.HasPrefix(got.Anchorctl, "/proc/self/fd/") {
			t.Errorf("a run that is up, on Linux: %+v, %v; want an anchorctl in memory", got, err)
		}
	} else if !errors.Is(err, libexec.ErrNotExtracted) {
		t.Errorf("a run with no pair: %v, want ErrNotExtracted", err)
	}

	if entries, _ := os.ReadDir(d.Libexec()); len(entries) > 0 {
		t.Errorf("a reader wrote %d entries into the run's %s", len(entries), d.Libexec())
	}

	if runtime.GOOS != "linux" {
		extracted, err := libexec.Ensure(d) // as the run does
		if err != nil {
			t.Fatal(err)
		}

		got, err := toolsFor(d)
		if err != nil || got.Anchorctl != extracted.Anchorctl {
			t.Errorf("a run that is up: %+v, %v; want %s", got, err, extracted.Anchorctl)
		}
	}

	// An installed root is the reader's own to extract into, as it always was.
	t.Cleanup(paths.UseRoot(t.TempDir()))

	if _, err := toolsFor(paths.Default()); err != nil {
		t.Errorf("an installed root: %v", err)
	}
}
