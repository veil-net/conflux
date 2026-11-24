package libexec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/paths"
)

// TestInMemoryRunsWithNoFile: an ephemeral run's pair is sealed memory, run by its
// /proc/self/fd name, with no file of it anywhere and nothing that can change it once made.
func TestInMemoryRunsWithNoFile(t *testing.T) {
	anchortest.Require(t)

	tools, err := InMemory()
	if err != nil {
		t.Fatalf("InMemory: %v", err)
	}

	if tools.Dir != "" {
		t.Errorf("the pair in memory names a directory, %s", tools.Dir)
	}

	for _, bin := range []string{tools.Anchord, tools.Anchorctl} {
		if !strings.HasPrefix(bin, "/proc/self/fd/") {
			t.Errorf("%s is not a descriptor of this process", bin)

			continue
		}

		if target, err := os.Readlink(bin); err != nil || !strings.HasPrefix(target, "/memfd:") {
			t.Errorf("%s is %q (%v), not a memory file", bin, target, err)
		}

		if f, err := os.OpenFile(bin, os.O_WRONLY, 0); err == nil {
			_, werr := f.Write([]byte("x"))
			_ = f.Close()

			if werr == nil {
				t.Errorf("%s could be written after it was sealed", bin)
			}
		}
	}

	if out, err := exec.Command(tools.Anchorctl, "help").CombinedOutput(); err != nil {
		t.Fatalf("anchorctl help from memory: %v\n%s", err, out)
	}

	again, err := InMemory()
	if err != nil || again.Anchord != tools.Anchord {
		t.Errorf("a second InMemory made another pair: %v, %v", again, err)
	}
}

// TestAnchorctlInMemoryIsAnchorctlAlone: a reader of an ephemeral run, or help, takes the
// anchorctl it carries without making an anchord it will not run.
func TestAnchorctlInMemoryIsAnchorctlAlone(t *testing.T) {
	anchortest.Require(t)

	tools, err := AnchorctlInMemory()
	if err != nil {
		t.Fatalf("AnchorctlInMemory: %v", err)
	}

	if tools.Anchord != "" || !strings.HasPrefix(tools.Anchorctl, "/proc/self/fd/") {
		t.Errorf("AnchorctlInMemory = %+v", tools)
	}
}

// TestForUsageWritesNothing: help asks an anchorctl in memory, and puts no copy of it in a
// temporary directory.
func TestForUsageWritesNothing(t *testing.T) {
	anchortest.Require(t)

	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)

	bin, done, err := ForUsage(paths.Dirs{Root: filepath.Join(t.TempDir(), "nothing-extracted")})
	if err != nil {
		t.Fatal(err)
	}
	defer done()

	if !strings.HasPrefix(bin, "/proc/self/fd/") {
		t.Errorf("help asks %s, not an anchorctl in memory", bin)
	}

	if entries, _ := os.ReadDir(tmp); len(entries) > 0 {
		t.Errorf("help wrote %d entries into the temporary directory", len(entries))
	}
}
