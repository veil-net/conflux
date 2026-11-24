package libexec

import (
	"errors"
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

	bin, done, temporary, err := ForUsage(paths.Dirs{Root: filepath.Join(t.TempDir(), "nothing-extracted")})
	if err != nil {
		t.Fatal(err)
	}
	defer done()

	if !strings.HasPrefix(bin, "/proc/self/fd/") || temporary {
		t.Errorf("help asks %s, temporary %v, not an anchorctl in memory", bin, temporary)
	}

	if entries, _ := os.ReadDir(tmp); len(entries) > 0 {
		t.Errorf("help wrote %d entries into the temporary directory", len(entries))
	}
}

// TestStartsIsExecvesAnswer: what decides whether a reader or help takes anchorctl from memory
// is whether it can be started at all, so each of the ways execve refuses -- no permission to
// run it, no program in it, no file at the name -- is ErrNoMemoryExec, which sends the caller
// to its next source, and a program that starts is taken.
func TestStartsIsExecvesAnswer(t *testing.T) {
	dir := t.TempDir()

	write := func(name, body string, mode os.FileMode) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}

		return path
	}

	for name, path := range map[string]string{
		"not executable": write("plain", "#!/bin/sh\nexit 0\n", 0o600),
		"no program":     write("text", "not a program\n", 0o700),
		"no file":        filepath.Join(dir, "missing"),
	} {
		if err := starts(path); !errors.Is(err, ErrNoMemoryExec) {
			t.Errorf("%s: starts = %v, want ErrNoMemoryExec", name, err)
		}
	}

	if err := starts(write("program", "#!/bin/sh\nexit 0\n", 0o700)); err != nil {
		t.Errorf("a program that starts: %v", err)
	}
}
