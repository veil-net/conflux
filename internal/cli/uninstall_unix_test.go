//go:build !windows

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/pathstest"
	"github.com/veil-net/conflux/internal/privcheck"
)

// plantLink makes link a symbolic link to target.
func plantLink(t *testing.T, link, target string) {
	t.Helper()

	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

// plantForeign makes path a file another account owns: nobody's, where this test runs as root, and
// otherwise one whose mode lets nobody read or write it, its owner included -- a file uninstall can
// only remove as itself, never open, as root removes another account's.
func plantForeign(t *testing.T, path string) {
	t.Helper()

	if err := os.WriteFile(path, []byte("planted"), 0o000); err != nil {
		t.Fatal(err)
	}

	if os.Geteuid() == 0 {
		if err := os.Chown(path, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
}

// TestUninstallRemovesTheWayConfluxMade: the folders conflux made on the way to a CONFLUX_DIR, which
// EnsureAll records in the root, go with it once empty, deepest first, and the folder they were made
// in stays -- where the readers' check refuses the root too: all a record somebody else wrote could
// lead to is removing an empty folder above conflux's roots.
func TestUninstallRemovesTheWayConfluxMade(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	for _, refused := range []bool{false, true} {
		t.Run(fmt.Sprintf("refused=%v", refused), func(t *testing.T) {
			above := t.TempDir()
			way := []string{filepath.Join(above, "made"), filepath.Join(above, "made", "by")}
			d := pathstest.DirsIn(t, filepath.Join(way[1], "conflux"))

			if refused {
				if err := os.Chmod(d.State, 0o757); err != nil {
					t.Fatal(err)
				}
			}

			standInService(t, &fakeManager{d: d})

			out, errOut, code := capture(t, "uninstall", "--yes")
			if code != ExitOK {
				t.Fatalf("uninstall exited %d:\n%s%s", code, out, errOut)
			}

			if _, err := os.Lstat(d.State); !os.IsNotExist(err) {
				t.Errorf("uninstall left %s (Lstat: %v)", d.State, err)
			}

			for _, p := range way {
				if _, err := os.Lstat(p); !os.IsNotExist(err) {
					t.Errorf("uninstall left %s, which conflux made on the way to its root (Lstat: %v)", p, err)
				}

				if !strings.Contains(out, "  "+p+"\n") {
					t.Errorf("uninstall did not say it removed %s:\n%s", p, out)
				}
			}

			if _, err := os.Stat(above); err != nil {
				t.Errorf("uninstall removed %s, which conflux did not make: %v", above, err)
			}
		})
	}
}

// TestUninstallRefusesAWayAnotherAccountMayChange: the one root uninstall refuses is a CONFLUX_DIR
// whose way another account may change -- inside a directory every account may write -- since whoever
// could change it could have put anything at the root's name, and conflux cannot know it is its own.
// It is refused before anything is removed, the boot service included, exit 1, naming the directory
// and saying how to uninstall, not how to choose a CONFLUX_DIR.
func TestUninstallRefusesAWayAnotherAccountMayChange(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	parent := t.TempDir()
	d := pathstest.DirsIn(t, filepath.Join(parent, "conflux"))

	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })

	mgr := &removing{fakeManager: fakeManager{d: d}}
	standInService(t, mgr)

	out, errOut, code := capture(t, "uninstall", "--yes")
	if code != ExitError || !strings.Contains(errOut, parent) || !strings.Contains(errOut, "conflux uninstall") ||
		strings.Contains(errOut, "Choose a CONFLUX_DIR") {
		t.Errorf("uninstall of a root in a directory every account may write exited %d, want %d naming it and "+
			"saying how to uninstall:\n%s%s", code, ExitError, out, errOut)
	}

	if _, err := os.Lstat(d.State); mgr.removals > 0 || err != nil {
		t.Errorf("uninstall, refusing the way, removed the boot service %d times, and %s (Lstat: %v)", mgr.removals,
			d.State, err)
	}
}
