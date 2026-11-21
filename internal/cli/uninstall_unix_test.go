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
// in stays. Where the readers' check refuses the root, the root still goes, but its record is not
// read -- whoever could change the root could have written it -- so those folders are left, and
// uninstall says why.
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
				_, err := os.Lstat(p)

				switch {
				case refused && err != nil:
					t.Errorf("uninstall removed %s, recorded in a root the readers' check refuses: %v", p, err)
				case !refused && !os.IsNotExist(err):
					t.Errorf("uninstall left %s, which conflux made on the way to its root (Lstat: %v)", p, err)
				case !refused && !strings.Contains(out, "  "+p+"\n"):
					t.Errorf("uninstall did not say it removed %s:\n%s", p, out)
				}
			}

			if refused != strings.Contains(errOut, "the folders conflux made on the way to "+d.State+" were left") {
				t.Errorf("uninstall of a root refused=%v said:\n%s", refused, errOut)
			}

			if _, err := os.Stat(above); err != nil {
				t.Errorf("uninstall removed %s, which conflux did not make: %v", above, err)
			}
		})
	}
}
