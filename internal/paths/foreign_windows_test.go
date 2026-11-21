package paths

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/privtest"
)

// TestAForeignRootIsLeftAsItIs: a root whose top level holds a name conflux never makes there is
// somebody else's, and is refused and left untouched, the stray name in the refusal: a CONFLUX_DIR at a
// folder of homes, alice\ and bob\ in it, by EnsureAll, by uninstall's pre-flight (JudgeWays, as a
// foreign root) and by RemoveRoot, its DACL and what it holds as they were; and a junction at the root's
// name, once a root of conflux's, which secure made its own, repointed at that folder, the same way,
// the junction left too. A fresh empty folder, and a root of conflux's holding what conflux makes, are
// taken. Windows-only, so it runs in CI's platforms job alone.
func TestAForeignRootIsLeftAsItIs(t *testing.T) {
	base := t.TempDir()

	homes := filepath.Join(base, "home")
	for _, home := range []string{"alice", "bob"} {
		if err := os.MkdirAll(filepath.Join(homes, home), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	// asFound is the folder's DACL's entries and the names it holds.
	asFound := func() (int, []string) {
		entries, err := os.ReadDir(homes)
		if err != nil {
			t.Fatal(err)
		}

		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}

		return len(privtest.ReadSecurity(t, homes).Entries), names
	}

	ours := filepath.Join(base, "ours")
	t.Setenv("CONFLUX_DIR", ours)

	if err := Default().EnsureAll(); err != nil {
		t.Fatalf("EnsureAll(a CONFLUX_DIR not there) = %v", err)
	}

	if err := os.WriteFile(Default().ManifestFile(), []byte("identity"), 0o600); err != nil {
		t.Fatal(err)
	}

	link := mklinkJ(t, filepath.Join(base, "conflux"), ours)
	t.Setenv("CONFLUX_DIR", link)

	if err := Default().EnsureAll(); err != nil {
		t.Fatalf("EnsureAll(a junction to a root of conflux's) = %v, want it taken", err)
	}

	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}

	mklinkJ(t, link, homes)

	for _, root := range []string{homes, link} {
		t.Run(filepath.Base(root), func(t *testing.T) {
			t.Setenv("CONFLUX_DIR", root)

			grants, held := asFound()

			if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), "holds alice") {
				t.Errorf("EnsureAll(a CONFLUX_DIR of %s) = %v, want a refusal naming alice", root, err)
			}

			if err := Default().JudgeWays(); !errors.Is(err, ErrForeignRoot) || errors.Is(err, ErrWayRefused) ||
				!strings.Contains(err.Error(), "holds alice") {
				t.Errorf("JudgeWays(a CONFLUX_DIR of %s) = %v, want a refusal of a foreign root naming alice", root, err)
			}

			if gone, err := RemoveRoot(root); gone || err == nil || !strings.Contains(err.Error(), "holds alice") {
				t.Errorf("RemoveRoot(%s) = %v, %v, want a refusal naming alice", root, gone, err)
			}

			if g, h := asFound(); g != grants || !slices.Equal(h, held) {
				t.Errorf("a CONFLUX_DIR of %s was left %d entries holding %q, want %d holding %q", root, g, h, grants,
					held)
			}

			if _, err := os.Lstat(root); err != nil {
				t.Errorf("a CONFLUX_DIR of %s refused is not there: %v", root, err)
			}
		})
	}

	empty := filepath.Join(base, "empty")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONFLUX_DIR", empty)

	if err := Default().JudgeWays(); err != nil {
		t.Errorf("JudgeWays(a CONFLUX_DIR of a fresh empty folder) = %v", err)
	}

	if err := Default().EnsureAll(); err != nil {
		t.Errorf("EnsureAll(a CONFLUX_DIR of a fresh empty folder) = %v, want it taken", err)
	}

	t.Setenv("CONFLUX_DIR", ours)

	if err := Default().JudgeWays(); err != nil {
		t.Errorf("JudgeWays(a root of conflux's) = %v", err)
	}

	if gone, err := RemoveRoot(ours); !gone || err != nil {
		t.Errorf("RemoveRoot(a root of conflux's) = %v, %v, want it removed", gone, err)
	}
}
