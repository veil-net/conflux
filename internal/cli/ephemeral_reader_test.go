package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/flock"
	"github.com/veil-net/conflux/internal/libexec"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/pathstest"
)

// startingEphemeral is an ephemeral root as a run that has just taken its lock finds it
// after another was killed: the lock held, the killed run's socket still there, and its
// extracted binaries half cleared away.
func startingEphemeral(t *testing.T) paths.Dirs {
	t.Helper()

	d := ephemeralRoot(t)
	t.Cleanup(holdRoot(t, d))

	if err := os.MkdirAll(filepath.Dir(d.Socket()), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(d.Socket(), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	return d
}

// ephemeralRoot is the root an ephemeral run is kept in, in a runtime folder of the test's own
// (pathstest.Runtime), not made yet.
func ephemeralRoot(t *testing.T) paths.Dirs {
	t.Helper()

	pathstest.Runtime(t, t.TempDir())

	d, err := paths.EphemeralDirs()
	if err != nil {
		t.Fatal(err)
	}

	return d
}

// holdRoot makes d's roots, as a supervisor or a run does, and takes the lock it holds while it
// runs: what lets that go.
func holdRoot(t *testing.T, d paths.Dirs) (unlock func()) {
	t.Helper()

	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	unlock, ok, err := flock.TryAcquire(d.ServeLockFile())
	if err != nil || !ok {
		t.Fatalf("take the lock a supervisor holds: %v", err)
	}

	return unlock
}

// TestStatusWritesNothingIntoAStartingEphemeralRun: status, asked while an ephemeral run is
// clearing what a killed one left, neither extracts binaries into the run's root nor asks
// its daemon. Extracting there is what raced the run's own clearing, which then found the
// directory it was emptying refilled.
func TestStatusWritesNothingIntoAStartingEphemeralRun(t *testing.T) {
	anchortest.Require(t)

	pathstest.Dirs(t) // the installation status reads too, beside the run

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

	pathstest.Dirs(t) // the installation status reads too, beside the run

	d := startingEphemeral(t)

	killed := exec.Command(os.Args[0], "-test.run=^$")
	if err := killed.Run(); err != nil {
		t.Fatalf("run a process to end: %v", err)
	}

	marker := fmt.Sprintf("%s anchorkilled %d\n", time.Now().UTC().Format(time.RFC3339Nano), killed.ProcessState.Pid())
	if err := os.WriteFile(d.ReadyFile(), []byte(marker), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, _, err := toolsFor(t.Context(), d); !errors.Is(err, errEphemeralStarting) {
		t.Errorf("a reader, with the killed run's marker beside the new run's lock: %v, want errEphemeralStarting", err)
	}

	if out, _, _ := capture(t, "status"); !strings.Contains(out, "starting, from "+d.State) {
		t.Errorf("status, with the killed run's marker beside the new run's lock, does not say it is starting:\n%s", out)
	}
}

// TestAReaderTakesAnEphemeralRunsPairAsItIs: before the run marks itself up, a reader is
// told it is starting; after, it gets the pair the run extracted, and where the run has
// none it is told so -- in neither case writing anything into the run's root.
func TestAReaderTakesAnEphemeralRunsPairAsItIs(t *testing.T) {
	anchortest.Require(t)

	d := startingEphemeral(t)

	if _, _, err := toolsFor(t.Context(), d); !errors.Is(err, errEphemeralStarting) {
		t.Errorf("before the run is up: %v, want errEphemeralStarting", err)
	}

	if err := daemon.MarkReady(d, "anchorx"); err != nil {
		t.Fatal(err)
	}

	if _, _, err := toolsFor(t.Context(), d); !errors.Is(err, libexec.ErrNotExtracted) {
		t.Errorf("a run with no pair: %v, want ErrNotExtracted", err)
	}

	if entries, _ := os.ReadDir(d.Libexec()); len(entries) > 0 {
		t.Errorf("a reader wrote %d entries into the run's %s", len(entries), d.Libexec())
	}

	extracted, err := libexec.Extract(t.Context(), d) // as the run does
	if err != nil {
		t.Fatal(err)
	}

	got, done, err := toolsFor(t.Context(), d)
	if err != nil || got != extracted.Anchorctl || done != nil {
		t.Errorf("a run that is up: %s, %v; want %s, and nothing to remove", got, err, extracted.Anchorctl)
	}
}

// TestAReaderRemakesNothing: a reader -- status, renew, a pass-through -- makes neither a root nor the bin
// directory in the installation, which a service may be running from, and leaves its roots as they are
// -- a run directory not as conflux makes it among them, which EnsureAll would make afresh, the token in
// it with it. Where this build's pair is not extracted there, as once an upgrade has put a newer conflux
// in place, and there is no bin directory to extract it into, it runs a private temporary copy of
// anchorctl, which done removes; where the bin directory is there, as conflux makes it, the pair is
// extracted into it, and the reader runs that, with nothing to remove, as it does once the pair is there.
func TestAReaderRemakesNothing(t *testing.T) {
	anchortest.Require(t)

	d := pathstest.Dirs(t)

	if err := os.Remove(d.Libexec()); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(d.TokenFile(), []byte("token"), 0o600); err != nil {
		t.Fatal(err)
	}

	pathstest.NotAsConfluxMakesIt(t, d.Run)

	bin, done, err := toolsFor(t.Context(), d)
	if err != nil || done == nil || strings.HasPrefix(bin, d.State) {
		t.Fatalf("a reader of an installation with no bin directory = %s, %v, want a temporary copy to remove", bin,
			err)
	}

	if _, err := os.Stat(d.TokenFile()); err != nil {
		t.Errorf("a reader remade the installation's run directory, the token in it with it: %v", err)
	}

	if _, err := os.Lstat(d.Libexec()); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a reader made the installation's bin directory (Lstat %s: %v)", d.Libexec(), err)
	}

	done()

	if _, err := os.Lstat(bin); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("done left the temporary copy %s (Lstat: %v)", bin, err)
	}

	if err := os.Mkdir(d.Libexec(), 0o700); err != nil {
		t.Fatal(err)
	}

	bin, done, err = toolsFor(t.Context(), d)

	extracted, extractErr := libexec.Extracted(d)
	if err != nil || extractErr != nil || bin != extracted.Anchorctl || done != nil {
		t.Errorf("a reader of an installation with a bin directory and no pair extracted = %s, %v, want the pair "+
			"extracted there (%v), and nothing to remove", bin, err, extractErr)
	}

	if _, err := os.Stat(d.TokenFile()); err != nil {
		t.Errorf("a reader's extraction remade the installation's run directory, the token in it with it: %v", err)
	}
}

// TestAReaderPassesOverARootAnotherAccountMade: a root another account made, with a held lock, a
// readiness marker and an anchorctl of its own in it, is no run's -- a run will not be kept in one -- so
// status and pass-through pass it over, and nothing runs what it holds. Nor do they look inside it
// first: a link there could lead them anywhere its maker chose.
func TestAReaderPassesOverARootAnotherAccountMade(t *testing.T) {
	d := startingEphemeral(t)

	if err := daemon.MarkReady(d, "anchorx"); err != nil {
		t.Fatal(err)
	}

	looked := 0

	defer func(was func(string) (os.FileInfo, error)) { statLock = was }(statLock)
	statLock = func(name string) (os.FileInfo, error) {
		if strings.HasPrefix(name, d.State+string(filepath.Separator)) {
			looked++
		}

		return os.Stat(name)
	}

	foreign := true

	defer func(was func(paths.Dirs) error) { checkEphemeral = was }(checkEphemeral)
	checkEphemeral = func(e paths.Dirs) error {
		if foreign && e.State == d.State {
			return errors.New(e.State + " belongs to another account")
		}

		return nil
	}

	if live, stale := ephemeralRuns(); live != nil || stale != nil {
		t.Errorf("a root another account made, with a held lock and a marker, was taken for a run: live %v, stale %v", live, stale)
	}

	if looked > 0 {
		t.Errorf("a root another account made was looked inside %d times before it was passed over", looked)
	}

	// The same root, this account's, is looked in, and is the run.
	foreign = false

	if live, _ := ephemeralRuns(); live == nil || live.State != d.State || looked == 0 {
		t.Errorf("this account's root, looked inside %d times, gave the run %v, want %s", looked, live, d.State)
	}
}

// TestAReaderReadsNothingOfARootNotThere: an ephemeral root that is not there when a reader asks
// whose it is holds no run, and nothing more is looked up at its name: whatever is made there a moment
// later, with a lock, held or left, a marker and an anchorctl in it, is whoever made it first's, and taken
// for a run it would have a pass-through reach their daemon and run their anchorctl. So a root made just
// after the readers' check found none there is neither the live run nor a stale one, and not looked
// inside.
func TestAReaderReadsNothingOfARootNotThere(t *testing.T) {
	for name, held := range map[string]bool{"a run's lock held": true, "a killed run's lock left": false} {
		t.Run(name, func(t *testing.T) {
			d := ephemeralRoot(t)

			looked := 0

			defer func(was func(string) (os.FileInfo, error)) { statLock = was }(statLock)
			statLock = func(name string) (os.FileInfo, error) {
				if strings.HasPrefix(name, d.State+string(filepath.Separator)) {
					looked++
				}

				return os.Stat(name)
			}

			// The readers' check's answer for a root not there, and the root made, a run's in all but who
			// made it, the moment after.
			defer func(was func(paths.Dirs) error) { checkEphemeral = was }(checkEphemeral)
			checkEphemeral = func(e paths.Dirs) error {
				if _, err := os.Lstat(e.State); !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("%s is there before it is planted (%v)", e.State, err)
				}

				plantRun(t, d, held)

				return fmt.Errorf("%s: %w", e.State, fs.ErrNotExist)
			}

			if live, stale := ephemeralRuns(); live != nil || stale != nil {
				t.Errorf("a root made after it was found not there was taken for a run: live %v, stale %v", live, stale)
			}

			if looked > 0 {
				t.Errorf("a root made after it was found not there was looked inside %d times", looked)
			}
		})
	}
}

// plantRun makes d a run's root, marked up, its lock held for the rest of the test where held is
// set, and left as a killed run leaves it otherwise.
func plantRun(t *testing.T, d paths.Dirs, held bool) {
	t.Helper()

	unlock := holdRoot(t, d)
	if held {
		t.Cleanup(unlock)
	} else {
		unlock()
	}

	if err := daemon.MarkReady(d, "anchorplanted"); err != nil {
		t.Fatal(err)
	}
}
