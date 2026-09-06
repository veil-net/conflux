package libexec

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/internal/paths"
)

func dirs(t *testing.T) paths.Dirs {
	t.Helper()
	t.Setenv("CONFLUX_DIR", t.TempDir())

	d := paths.Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatalf("EnsureAll: %v", err)
	}

	return d
}

func TestEnsureExtractsAndRuns(t *testing.T) {
	if !anchor.Supported {
		t.Skip("no anchor pair for this platform")
	}

	d := dirs(t)

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
// rewrote 43 MB would make the CLI feel broken.
func TestEnsureIsIdempotent(t *testing.T) {
	if !anchor.Supported {
		t.Skip("no anchor pair for this platform")
	}

	d := dirs(t)

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
// starting conflux at once. All of them must agree on one directory, and none must
// see a half-written binary.
func TestEnsureIsConcurrencySafe(t *testing.T) {
	if !anchor.Supported {
		t.Skip("no anchor pair for this platform")
	}

	if testing.Short() {
		t.Skip("extracts 43 MB")
	}

	d := dirs(t)

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

	// And exactly one set directory exists, with no staging debris left behind.
	entries, err := os.ReadDir(d.Libexec())
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}

	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".staging-") {
			t.Errorf("a staging directory survived: %s", e.Name())
		}
	}
}

// TestEnsureRepairsATruncatedExtraction: a marker alone is not proof. A power cut
// mid-write can leave a short binary, and re-running must fix it rather than trust
// the marker and hand back a corpse.
func TestEnsureRepairsATruncatedExtraction(t *testing.T) {
	if !anchor.Supported {
		t.Skip("no anchor pair for this platform")
	}

	d := dirs(t)

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
