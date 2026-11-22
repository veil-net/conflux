package libexec

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/flock"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/pathstest"
)

func TestExtractExtractsAndRuns(t *testing.T) {
	anchortest.Require(t)

	d := pathstest.Dirs(t)

	tools, err := Extract(d)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	if tools.SetID != anchor.SetID() {
		t.Errorf("SetID = %q, want %q", tools.SetID, anchor.SetID())
	}

	if !strings.HasSuffix(filepath.Dir(tools.Anchord), tools.SetID) {
		t.Errorf("Anchord is at %s, which is not under the set directory", tools.Anchord)
	}

	for _, p := range []string{tools.Anchord, tools.Anchorctl} {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}

		if runtime.GOOS != "windows" && fi.Mode().Perm()&0o100 == 0 {
			t.Errorf("%s is mode %o and not executable", p, fi.Mode().Perm())
		}
	}

	// The point of all of it: the thing on disk is the thing that runs.
	out, err := exec.Command(tools.Anchorctl, "help").CombinedOutput()
	if err != nil {
		t.Fatalf("the extracted anchorctl did not run: %v\n%s", err, out)
	}

	if !strings.Contains(string(out), "anchorctl") {
		t.Errorf("anchorctl help said something unexpected:\n%s", out)
	}
}

// TestExtractionMakesNoRootNorBinDirectory: an extraction makes the set in the bin directory and nothing
// else. EnsureAll makes the bin directory with the roots, and one gone since -- uninstall removing the
// root under a reader that judged it a moment before -- fails the extraction, the bin directory and the
// root made again by nobody.
func TestExtractionMakesNoRootNorBinDirectory(t *testing.T) {
	anchortest.Require(t)

	d := pathstest.Dirs(t)

	if fi, err := os.Lstat(d.Libexec()); err != nil || !fi.IsDir() {
		t.Errorf("EnsureAll did not make the bin directory %s (%v)", d.Libexec(), err)
	}

	for _, gone := range []string{d.Libexec(), d.State} {
		if err := os.RemoveAll(gone); err != nil {
			t.Fatal(err)
		}

		if _, err := Extract(d); err == nil {
			t.Errorf("Extract with %s gone succeeded", gone)
		}

		if _, err := os.Lstat(gone); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("Extract made %s again (Lstat: %v)", gone, err)
		}
	}
}

// TestRemakeWaitsForAnExtractionInProgress: Remake empties bin/ under its lock, which a reader extracting
// a set holds for as long as that takes, so it waits for the lock -- here held past TryAcquire's own
// tries -- and then empties bin/ and extracts afresh; held past its bound (lockWait), it refuses, saying
// another conflux is extracting, with nothing removed. The holder lets go on a timer whatever Remake
// does, so a Remake that waited without a bound would end, and fail the test, rather than hang it.
func TestRemakeWaitsForAnExtractionInProgress(t *testing.T) {
	anchortest.Require(t)

	d := pathstest.Dirs(t)
	older := filepath.Join(d.Libexec(), "0123456789abcdef")

	hold := func(d time.Duration) {
		unlock, err := flock.Acquire(filepath.Join(filepath.Dir(older), ".lock"))
		if err != nil {
			t.Fatal(err)
		}

		release := sync.OnceFunc(unlock)
		time.AfterFunc(d, release)
		t.Cleanup(release)
	}

	if err := os.Mkdir(older, 0o700); err != nil {
		t.Fatal(err)
	}

	hold(200 * time.Millisecond)

	if removed, err := Remake(d); err != nil || !slices.Contains(removed, older) {
		t.Errorf("Remake beside an extraction that ends in 200 ms = %v, %v, want %s removed once it has", removed, err,
			older)
	}

	defer func(was time.Duration) { lockWait = was }(lockWait)
	lockWait = 100 * time.Millisecond

	if err := os.Mkdir(older, 0o700); err != nil {
		t.Fatal(err)
	}

	hold(5 * time.Second)

	if _, err := Remake(d); err == nil || !strings.Contains(err.Error(), "another conflux is extracting") {
		t.Errorf("Remake beside an extraction past its bound = %v, want a refusal saying another conflux is extracting",
			err)
	}

	if _, err := os.Stat(older); err != nil {
		t.Errorf("Remake past its bound removed %s: %v", older, err)
	}
}

// TestExtractIsIdempotent asserts the hot path does no work. Every start, and every reader
// once the pair is there, calls Extract, so a second call that rewrote the pair would make
// the CLI feel broken.
func TestExtractIsIdempotent(t *testing.T) {
	anchortest.Require(t)

	d := pathstest.Dirs(t)

	first, err := Extract(d)
	if err != nil {
		t.Fatalf("first Extract: %v", err)
	}

	before, err := os.Stat(first.Anchord)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	second, err := Extract(d)
	if err != nil {
		t.Fatalf("second Extract: %v", err)
	}

	if second.Dir != first.Dir {
		t.Errorf("second Extract chose %s, first chose %s", second.Dir, first.Dir)
	}

	after, err := os.Stat(second.Anchord)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if !before.ModTime().Equal(after.ModTime()) {
		t.Error("the second Extract rewrote the binary; it should have been a stat and nothing else")
	}
}

// TestExtractIsConcurrencySafe is the boot case: the service and an operator both
// starting conflux at once. All of them must agree on one directory, and leave that one
// set and nothing else behind them.
func TestExtractIsConcurrencySafe(t *testing.T) {
	anchortest.Require(t)

	d := pathstest.Dirs(t)

	const n = 8

	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		paths = make([]string, 0, n)
		errs  = make([]error, 0, n)
	)

	for range n {
		wg.Add(1)

		go func() {
			defer wg.Done()

			tools, err := Extract(d)

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				errs = append(errs, err)

				return
			}

			paths = append(paths, tools.Anchord)
		}()
	}

	wg.Wait()

	if len(errs) > 0 {
		t.Fatalf("%d of %d concurrent Extract calls failed: %v", len(errs), n, errs[0])
	}

	for _, p := range paths {
		if p != paths[0] {
			t.Fatalf("concurrent callers disagreed: %s and %s", p, paths[0])
		}
	}

	// And exactly one directory exists, the set, with no staging debris left behind.
	entries, err := os.ReadDir(d.Libexec())
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}

	var sets int

	for _, e := range entries {
		switch {
		case !e.IsDir():
		case e.Name() == anchor.SetID():
			sets++
		default:
			t.Errorf("a directory other than the set survived: %s", e.Name())
		}
	}

	if sets != 1 {
		t.Errorf("%d set directories, want 1", sets)
	}
}

// TestASetThatWillNotRunIsRemoved: an extraction whose anchorctl does not run is not left in
// place, under its name or in staging, where the next conflux would take it as whole and fail
// at every start with less said, and the next Extract extracts it again.
func TestASetThatWillNotRunIsRemoved(t *testing.T) {
	anchortest.Require(t)

	d := pathstest.Dirs(t)

	refused := errors.New("the stand-in smoke run refused it")

	smokeRun = func(*Tools) error { return refused }
	t.Cleanup(func() { smokeRun = smoke })

	if _, err := Extract(d); !errors.Is(err, refused) {
		t.Fatalf("Extract with a failing smoke run = %v, want its refusal", err)
	}

	entries, err := os.ReadDir(d.Libexec())
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}

	for _, e := range entries {
		if e.IsDir() {
			t.Errorf("%s is left after a smoke run that failed", e.Name())
		}
	}

	smokeRun = smoke

	if _, err := Extract(d); err != nil {
		t.Errorf("the next Extract did not extract the set again: %v", err)
	}
}

// TestASetTakesItsNameOnlyOnceItHasRun: nothing is under a set's name until its smoke run has
// passed. Otherwise another conflux's Extract, finding it there meanwhile, takes it as whole
// unrun, and so does every later one when the run is interrupted -- conflux killed, the power
// cut -- since a whole set is never run again.
func TestASetTakesItsNameOnlyOnceItHasRun(t *testing.T) {
	anchortest.Require(t)

	d := pathstest.Dirs(t)
	set := toolsIn(d).Dir

	var smoked int

	smokeRun = func(staged *Tools) error {
		smoked++

		if _, err := os.Stat(set); err == nil {
			t.Errorf("%s is under its name while its smoke run has not ended", set)
		}

		if _, err := Extracted(d); !errors.Is(err, ErrNotExtracted) {
			t.Errorf("a concurrent conflux would take the set as whole before its smoke run ended (%v)", err)
		}

		return smoke(staged)
	}
	t.Cleanup(func() { smokeRun = smoke })

	if _, err := Extract(d); err != nil {
		t.Fatalf("Extract: %v", err)
	}

	if smoked != 1 {
		t.Errorf("the set was smoked %d times, want 1", smoked)
	}
}

// TestExtractRepairsATruncatedExtraction: a set under its name is taken as whole only
// at its sizes. A binary cut short since it was extracted -- by a damaged disk, or by
// hand -- is extracted again rather than handed back as a corpse.
func TestExtractRepairsATruncatedExtraction(t *testing.T) {
	anchortest.Require(t)

	d := pathstest.Dirs(t)

	tools, err := Extract(d)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}

	if err := os.WriteFile(tools.Anchord, []byte("truncated"), 0o700); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	again, err := Extract(d)
	if err != nil {
		t.Fatalf("second Extract: %v", err)
	}

	fi, err := os.Stat(again.Anchord)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if fi.Size() != int64(len(anchor.Anchord())) {
		t.Errorf("anchord is %d bytes after repair, want %d", fi.Size(), len(anchor.Anchord()))
	}
}

// TestSweepLeavesWhatMayBeInUse: Sweep keeps its own set and any set touched in the last
// day, which a supervisor still running an older conflux may be execing, and removes the
// rest, and a staging directory a crash left more than an hour ago.
func TestSweepLeavesWhatMayBeInUse(t *testing.T) {
	root := t.TempDir()

	age := map[string]time.Duration{
		"own":            48 * time.Hour,
		"recent":         time.Hour,
		"old":            48 * time.Hour,
		".staging-fresh": time.Minute,
		".staging-stale": 2 * time.Hour,
	}

	for name, a := range age {
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}

		then := time.Now().Add(-a)
		if err := os.Chtimes(dir, then, then); err != nil {
			t.Fatal(err)
		}
	}

	Sweep(&Tools{Dir: filepath.Join(root, "own"), SetID: "own"})

	for name, kept := range map[string]bool{
		"own": true, "recent": true, ".staging-fresh": true, "old": false, ".staging-stale": false,
	} {
		if _, err := os.Stat(filepath.Join(root, name)); (err == nil) != kept {
			t.Errorf("%s: kept = %v, want %v", name, err == nil, kept)
		}
	}
}

// TestUsageMakesNothing: help, asked where nothing is extracted -- before an install, after an
// uninstall, by an account that cannot read the installation -- runs a temporary anchorctl and
// removes it, and makes none of the installation's directories. Where a whole extraction is
// there it is the one used, and nothing is removed.
func TestUsageMakesNothing(t *testing.T) {
	anchortest.Require(t)

	// Its parent 0700 whatever the umask made it, as a CONFLUX_DIR's parents must be.
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONFLUX_DIR", filepath.Join(parent, "never"))
	pathstest.Temporary(t, t.TempDir())

	d := paths.Default()

	bin, done, err := forUsage(t, d)
	if err != nil {
		t.Fatalf("ForUsage: %v", err)
	}

	if out, err := exec.Command(bin, "help").CombinedOutput(); err != nil || !strings.Contains(string(out), "anchorctl") {
		t.Fatalf("the temporary anchorctl did not answer help: %v\n%s", err, out)
	}

	done()

	if _, err := os.Stat(filepath.Dir(bin)); !os.IsNotExist(err) {
		t.Errorf("the temporary anchorctl's directory is still there after done (%v)", err)
	}

	if _, err := os.Stat(os.Getenv("CONFLUX_DIR")); !os.IsNotExist(err) {
		t.Errorf("asking for usage made the installation's directories (%v)", err)
	}

	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	tools, err := Extract(d)
	if err != nil {
		t.Fatal(err)
	}

	if bin, done, err = forUsage(t, d); err != nil || bin != tools.Anchorctl || done != nil {
		t.Errorf("usage where %s is extracted = %s, %v, and done %v, want that, and nothing to remove",
			tools.Anchorctl, bin, err, done != nil)
	}
}

// forUsage is ForUsage of the installation d, its readers' check held first, the temporary copy it makes,
// where it makes one, removed once the test ends however it ends: before anything of it is asserted.
func forUsage(t *testing.T, d paths.Dirs) (string, func(), error) {
	t.Helper()

	bin, done, err := ForUsage(d, d.Check())
	if done != nil {
		t.Cleanup(done)
	}

	return bin, done, err
}

// TestAReaderExtractsIntoABinDirectoryOfConfluxs: a reader -- help, a status, a renew, a pass-through --
// of an installation whose roots pass the readers' check, with this build's pair not extracted, as once
// an upgrade has put a newer conflux in place, extracts it into the bin directory where that is there and
// as conflux makes it, beside the set an older conflux may be running, which it leaves; and runs it, with
// nothing to remove and nothing written to the temporary directory. Where there is no bin directory, it
// makes none, and runs a temporary copy it removes. Once extracted, the pair is taken as it is found:
// nothing in a root as conflux makes one is anybody else's, so its files are not judged.
func TestAReaderExtractsIntoABinDirectoryOfConfluxs(t *testing.T) {
	anchortest.Require(t)

	tmp := pathstest.Temporary(t, t.TempDir())
	d := pathstest.Dirs(t)

	if err := os.Remove(d.Libexec()); err != nil {
		t.Fatal(err)
	}

	bin, done, err := forUsage(t, d)
	if err != nil || done == nil || !strings.HasPrefix(bin, tmp+string(filepath.Separator)) {
		t.Fatalf("a reader with no bin directory = %s, %v, want a temporary copy in %s to remove", bin, err, tmp)
	}

	done()

	if _, err := os.Lstat(d.Libexec()); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a reader made the bin directory (Lstat %s: %v)", d.Libexec(), err)
	}

	older := filepath.Join(d.Libexec(), "0123456789abcdef")
	if err := os.MkdirAll(older, 0o700); err != nil {
		t.Fatal(err)
	}

	want := toolsIn(d)

	if bin, done, err := forUsage(t, d); err != nil || bin != want.Anchorctl || done != nil || !want.complete() {
		t.Errorf("a reader with this build's pair not extracted = %s, %v, and done %v, want %s extracted, and "+
			"nothing to remove", bin, err, done != nil, want.Anchorctl)
	}

	if _, err := os.Stat(older); err != nil {
		t.Errorf("a reader's extraction removed the set an older conflux runs: %v", err)
	}

	if left, _ := os.ReadDir(tmp); len(left) > 0 {
		t.Errorf("a reader left %v in the temporary directory", left)
	}

	pathstest.NotAsConfluxMakesIt(t, want.Anchorctl)

	if bin, done, err := forUsage(t, d); err != nil || bin != want.Anchorctl || done != nil {
		t.Errorf("a reader of the pair extracted, its anchorctl not as conflux makes it, = %s, %v, and done %v, "+
			"want %s as it is found", bin, err, done != nil, want.Anchorctl)
	}
}

// TestAReaderExtractsNothingIntoABinDirectoryNotOfConfluxs: where the bin directory is not as conflux makes
// a folder of its own (pathstest.NotAsConfluxMakesIt) a reader extracts nothing there, and runs a
// temporary copy it removes.
func TestAReaderExtractsNothingIntoABinDirectoryNotOfConfluxs(t *testing.T) {
	anchortest.Require(t)

	tmp := pathstest.Temporary(t, t.TempDir())
	d := pathstest.Dirs(t)

	pathstest.NotAsConfluxMakesIt(t, d.Libexec())

	bin, done, err := forUsage(t, d)
	if err != nil || done == nil || !strings.HasPrefix(bin, tmp+string(filepath.Separator)) {
		t.Fatalf("a reader of a bin directory not as conflux makes it = %s, %v, want a temporary copy in %s", bin,
			err, tmp)
	}

	if left, _ := os.ReadDir(d.Libexec()); len(left) > 0 {
		t.Errorf("a reader extracted %v into a bin directory not as conflux makes it", left)
	}
}

// TestUsageRunsNothingFromARootItRefuses: whoever may write a root could have put an anchorctl of
// their own where a set is extracted, with the set's name and sizes, so help runs an extraction
// only from a root that passes paths' check: in one not as conflux makes one
// (pathstest.NotAsConfluxMakesIt), it runs a private temporary copy, though a whole extraction is there.
func TestUsageRunsNothingFromARootItRefuses(t *testing.T) {
	anchortest.Require(t)

	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONFLUX_DIR", filepath.Join(parent, "conflux"))

	tmp := pathstest.Temporary(t, t.TempDir())

	d := paths.Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	planted, err := Extract(d)
	if err != nil {
		t.Fatal(err)
	}

	pathstest.NotAsConfluxMakesIt(t, d.State)

	bin, _, err := forUsage(t, d)
	if err != nil {
		t.Fatalf("ForUsage: %v", err)
	}

	if !strings.HasPrefix(bin, tmp+string(filepath.Separator)) {
		t.Errorf("help ran %s from a root not as conflux makes one, where %s is extracted; want a copy in %s",
			bin, planted.Anchorctl, tmp)
	}
}

// TestRemoveTemporaryRemovesWhatAKilledReaderLeft: a reader killed before it removed its temporary copy
// of anchorctl leaves the folder it made there for good, so uninstall and tidy remove every folder named as
// Temporary names one, everywhere a copy may be made for the account running them -- the temporary
// directory, and the user's cache directory, where one goes on a host whose temporary directory is mounted
// noexec, elevated on Windows as well -- and say which; anything else there is left, and so is a folder that
// will not go -- a reader's copy running from it, which Windows removes no file of -- passed over while the
// rest go. Each place is taken by its name as it is, never as a pattern: a temporary directory named x[1]
// leaves what is in x1.
func TestRemoveTemporaryRemovesWhatAKilledReaderLeft(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "x[1]")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}

	pathstest.Temporary(t, parent)

	left := []string{filepath.Join(parent, temporaryPrefix+"1"), filepath.Join(parent, temporaryPrefix+"2")}

	if cache, err := os.UserCacheDir(); err == nil {
		if err := os.MkdirAll(cache, 0o700); err != nil {
			t.Fatal(err)
		}

		left = append(left, filepath.Join(cache, temporaryPrefix+"4"))
	}
	inUse := filepath.Join(parent, temporaryPrefix+"3")
	others := []string{filepath.Join(parent, "conflux-other"), filepath.Join(filepath.Dir(parent), "x1", temporaryPrefix+"5")}

	for _, dir := range append(slices.Concat(left, others), inUse) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(dir, exeName("anchorctl")), []byte("a copy"), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	// A folder that will not go: a file in it held open on Windows, and on Unix one whose mode lets nothing
	// in it be removed, which holds nothing back from root.
	held := false

	switch {
	case runtime.GOOS == "windows":
		f, err := os.Open(filepath.Join(inUse, exeName("anchorctl")))
		if err != nil {
			t.Fatal(err)
		}

		defer f.Close()

		held = true
	case os.Geteuid() != 0:
		if err := os.Chmod(inUse, 0o500); err != nil {
			t.Fatal(err)
		}

		t.Cleanup(func() { _ = os.Chmod(inUse, 0o700) })

		held = true
	}

	removed := RemoveTemporary()

	for _, dir := range left {
		if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) || !slices.Contains(removed, dir) {
			t.Errorf("RemoveTemporary left %s (Lstat: %v), or did not say it removed it: %q", dir, err, removed)
		}
	}

	for _, other := range others {
		if _, err := os.Lstat(other); err != nil || slices.Contains(removed, other) {
			t.Errorf("RemoveTemporary removed %s, which is not one of temporary's (Lstat: %v): %q", other, err, removed)
		}
	}

	if _, err := os.Lstat(inUse); held && (err != nil || slices.Contains(removed, inUse)) {
		t.Errorf("RemoveTemporary removed %s, which will not go, or said it did (Lstat: %v): %q", inUse, err, removed)
	}
}

// TestUsageMakesNoTemporaryDirectory: help's copy goes in the system's temporary directory,
// which it never makes: one that is missing is left missing, and help says why it could not
// run rather than leaving a directory behind.
func TestUsageMakesNoTemporaryDirectory(t *testing.T) {
	anchortest.Require(t)

	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONFLUX_DIR", filepath.Join(parent, "never"))

	missing := pathstest.Temporary(t, filepath.Join(t.TempDir(), "tmp"))

	if bin, _, err := forUsage(t, paths.Default()); err == nil && strings.HasPrefix(bin, missing) {
		t.Errorf("help ran %s, from the temporary directory it made", bin)
	}

	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Errorf("help made the missing temporary directory %s (%v)", missing, err)
	}
}
