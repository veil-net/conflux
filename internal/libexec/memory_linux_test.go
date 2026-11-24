package libexec

import (
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/anchortest"
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
