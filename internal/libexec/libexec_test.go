package libexec

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/pathstest"
)

func TestEnsureExtractsAndRuns(t *testing.T) {
	anchortest.Require(t)

	d := pathstest.Dirs(t)

	tools, err := Ensure(d)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
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

// TestEnsureIsIdempotent asserts the hot path does no work. Every conflux
// invocation calls Ensure, including a bare pass-through, so a second call that
// rewrote the pair would make the CLI feel broken.
func TestEnsureIsIdempotent(t *testing.T) {
	anchortest.Require(t)

	d := pathstest.Dirs(t)

	first, err := Ensure(d)
	if err != nil {
		t.Fatalf("first Ensure: %v", err)
	}

	before, err := os.Stat(first.Anchord)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	second, err := Ensure(d)
	if err != nil {
		t.Fatalf("second Ensure: %v", err)
	}

	if second.Dir != first.Dir {
		t.Errorf("second Ensure chose %s, first chose %s", second.Dir, first.Dir)
	}

	after, err := os.Stat(second.Anchord)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if !before.ModTime().Equal(after.ModTime()) {
		t.Error("the second Ensure rewrote the binary; it should have been a stat and nothing else")
	}
}

// TestEnsureIsConcurrencySafe is the boot case: the service and an operator both
// starting conflux at once. All of them must agree on one directory, and leave that one
// set and nothing else behind them.
func TestEnsureIsConcurrencySafe(t *testing.T) {
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

			tools, err := Ensure(d)

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
		t.Fatalf("%d of %d concurrent Ensure calls failed: %v", len(errs), n, errs[0])
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
// at every start with less said, and the next Ensure extracts it again.
func TestASetThatWillNotRunIsRemoved(t *testing.T) {
	anchortest.Require(t)

	d := pathstest.Dirs(t)

	refused := errors.New("the stand-in smoke run refused it")

	smokeRun = func(*Tools) error { return refused }
	t.Cleanup(func() { smokeRun = smoke })

	if _, err := Ensure(d); !errors.Is(err, refused) {
		t.Fatalf("Ensure with a failing smoke run = %v, want its refusal", err)
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

	if _, err := Ensure(d); err != nil {
		t.Errorf("the next Ensure did not extract the set again: %v", err)
	}
}

// TestASetTakesItsNameOnlyOnceItHasRun: nothing is under a set's name until its smoke run has
// passed. Otherwise another conflux's Ensure, finding it there meanwhile, takes it as whole
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

	if _, err := Ensure(d); err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	if smoked != 1 {
		t.Errorf("the set was smoked %d times, want 1", smoked)
	}
}

// TestEnsureRepairsATruncatedExtraction: a set under its name is taken as whole only
// at its sizes. A binary cut short since it was extracted -- by a damaged disk, or by
// hand -- is extracted again rather than handed back as a corpse.
func TestEnsureRepairsATruncatedExtraction(t *testing.T) {
	anchortest.Require(t)

	d := pathstest.Dirs(t)

	tools, err := Ensure(d)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	if err := os.WriteFile(tools.Anchord, []byte("truncated"), 0o700); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	again, err := Ensure(d)
	if err != nil {
		t.Fatalf("second Ensure: %v", err)
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
	t.Setenv("TMPDIR", t.TempDir())

	d := paths.Default()

	bin, done, err := ForUsage(d)
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

	tools, err := Ensure(d)
	if err != nil {
		t.Fatal(err)
	}

	bin, done, err = ForUsage(d)
	if err != nil {
		t.Fatal(err)
	}

	done()

	if bin != tools.Anchorctl {
		t.Errorf("usage ran %s where %s is extracted", bin, tools.Anchorctl)
	}

	if _, err := os.Stat(bin); err != nil {
		t.Errorf("done removed the extracted anchorctl: %v", err)
	}
}

// TestAUsageCopyIsItsRunners: the anchorctl help runs from a temporary directory is restricted
// to the account running it, which need not be an administrator, and a set's binaries to the
// machine's. Only Windows acts on either, and its CI runs elevated, where Restrict's DACL lets
// the runner in as well, so it is the choice that is tested here.
func TestAUsageCopyIsItsRunners(t *testing.T) {
	is := func(got, want func(string, bool) error) bool {
		return reflect.ValueOf(got).Pointer() == reflect.ValueOf(want).Pointer()
	}

	if !is(restriction(true), paths.RestrictToOwner) {
		t.Error("a copy for one run is not restricted to its runner: an account that is not an administrator could not execute it")
	}

	if !is(restriction(false), paths.Restrict) {
		t.Error("a set's binaries are not restricted to SYSTEM and the Administrators")
	}
}
