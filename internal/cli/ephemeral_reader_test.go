package cli

import (
	"errors"
	"fmt"
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
)

// startingEphemeral is an ephemeral root as a run that has just taken its lock finds it
// after another was killed: the lock held, the killed run's socket still there, and its
// extracted binaries half cleared away.
func startingEphemeral(t *testing.T) paths.Dirs {
	t.Helper()

	// 0700 whatever the umask made it: the run's root is inside, and a parent its group
	// may write is refused.
	root := t.TempDir()
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONFLUX_DIR", root)

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

// TestAReaderPassesOverARootAnotherAccountMade: /tmp lets anybody make the name a user's
// ephemeral root has, and fill it with a held lock, a readiness marker and an anchorctl of
// their own. A root another account made is no run's -- a run will not be kept in one -- so
// status, pass-through and uninstall pass it over, and nothing runs what it holds. Nor do they
// look inside it first: a link there could lead them anywhere its maker chose.
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

	defer func(was func(string) error) { foreignRoot = was }(foreignRoot)
	foreignRoot = func(root string) error {
		if foreign && root == d.State {
			return errors.New(root + " belongs to another account")
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
