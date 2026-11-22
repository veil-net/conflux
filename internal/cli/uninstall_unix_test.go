//go:build !windows

package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
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

// TestUninstallJudgesNoFolderAboveARoot: the folder the root is in, and every folder above it, is the
// system's and not judged: uninstall of a root inside a directory every account may write removes it, the
// boot service with it, exit 0, and leaves the directory as it was.
func TestUninstallJudgesNoFolderAboveARoot(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	parent := t.TempDir()
	d := pathstest.DirsIn(t, parent)

	if err := os.Chmod(parent, 0o777); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })

	mgr := &removing{fakeManager: fakeManager{d: d}}
	standInService(t, mgr)
	recordAccounts(t)

	out, errOut, code := capture(t, "uninstall", "--yes")
	if code != ExitOK || mgr.removals != 1 {
		t.Errorf("uninstall of a root in a directory every account may write exited %d and removed the boot service "+
			"%d times, want %d and once:\n%s%s", code, mgr.removals, ExitOK, out, errOut)
	}

	if _, err := os.Lstat(d.State); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("uninstall left %s (Lstat: %v)", d.State, err)
	}

	if fi, err := os.Stat(parent); err != nil || fi.Mode().Perm() != 0o777 {
		t.Errorf("uninstall changed %s, which conflux did not make: %v, %v", parent, fi, err)
	}
}

// TestUninstallListsOnlyWhatIsGone: uninstall lists a root as removed only where it is gone: not one it
// could not empty -- a folder in it whose mode lets its owner remove nothing -- which it names in the
// failure instead, exit 1.
func TestUninstallListsOnlyWhatIsGone(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a folder whose mode lets its owner remove nothing in it holds nothing back from root")
	}

	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	d := configured(t)

	stuck := filepath.Join(d.Libexec(), "0123456789abcdef")
	if err := os.MkdirAll(stuck, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(stuck, "anchord"), []byte("an earlier set"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(stuck, 0o500); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = os.Chmod(stuck, 0o700) })

	standInService(t, &fakeManager{d: d})
	recordAccounts(t)

	out, errOut, code := capture(t, "uninstall", "--yes")
	if code != ExitError || !strings.Contains(errOut, stuck) {
		t.Errorf("uninstall of a root it could not empty exited %d, want %d naming why:\n%s%s", code, ExitError, out,
			errOut)
	}

	if _, err := os.Lstat(d.State); err != nil || strings.Contains(out, "  "+d.State+"\n") {
		t.Errorf("uninstall listed %s, which is still there, as removed (Lstat: %v):\n%s", d.State, err, out)
	}
}

// TestUninstallListsNoRootItFailedToRemove: a root that uninstall found something at the name of but
// could not remove is not listed as removed, whoever runs it: the failure names why instead, exit 1.
func TestUninstallListsNoRootItFailedToRemove(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	d := configured(t)

	errStuck := errors.New("the root would not empty")

	var asked []string

	defer func(was func(string) (bool, error)) { removeRoot = was }(removeRoot)
	removeRoot = func(dir string) (bool, error) {
		asked = append(asked, dir)

		return true, fmt.Errorf("%s: %w", dir, errStuck)
	}

	standInService(t, &fakeManager{d: d})
	recordAccounts(t)

	out, errOut, code := capture(t, "uninstall", "--yes")
	if code != ExitError || !strings.Contains(errOut, errStuck.Error()) {
		t.Errorf("uninstall of roots it could not remove exited %d, want %d naming why:\n%s%s", code, ExitError, out,
			errOut)
	}

	if !slices.Contains(asked, d.State) || strings.Contains(out, "  "+d.State+"\n") {
		t.Errorf("uninstall listed %s, which it could not remove, as removed, or did not remove it (asked %q):\n%s",
			d.State, asked, out)
	}
}
