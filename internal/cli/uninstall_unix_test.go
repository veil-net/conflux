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

	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/paths"
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
			recordAccounts(t)

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

// TestUninstallRefusesAWayAnotherAccountMayChange: among the roots uninstall refuses is a CONFLUX_DIR
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

// TestUninstallRemovesAnEphemeralRootNotAsConfluxMakesOne: an ephemeral run's root outside the
// installation's is conflux's by its name, so uninstall removes whatever is there: one not as conflux
// makes a root -- sticky, as /tmp is, one every account may write, or a link -- removed as itself,
// nothing in it read and no lock in it taken, where a link leads never touched; and a killed run's,
// at 0700 or at a 0755 nobody else may write, emptied under its lock. Each is listed.
func TestUninstallRemovesAnEphemeralRootNotAsConfluxMakesOne(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	d := configured(t)

	shared := filepath.Join(t.TempDir(), "conflux-ephemeral")
	open := filepath.Join(t.TempDir(), "conflux-ephemeral")
	killed := filepath.Join(t.TempDir(), "conflux-ephemeral")
	readable := filepath.Join(t.TempDir(), "conflux-ephemeral")

	for root, mode := range map[string]os.FileMode{shared: 0o777 | os.ModeSticky, open: 0o777, killed: 0o700,
		readable: 0o755} {
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(root, "serve.lock"), nil, 0o600); err != nil {
			t.Fatal(err)
		}

		if err := os.Chmod(root, mode); err != nil {
			t.Fatal(err)
		}
	}

	elsewhere := t.TempDir()

	kept := filepath.Join(elsewhere, "serve.lock")
	if err := os.WriteFile(kept, []byte("not conflux's"), 0o600); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(t.TempDir(), "conflux-ephemeral")
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Fatal(err)
	}

	defer func(was func() []string) { ephemeralCandidates = was }(ephemeralCandidates)
	ephemeralCandidates = func() []string { return []string{shared, open, link, killed, readable} }

	var emptied []string

	wasEmpty := removeEphemeral
	defer func() { removeEphemeral = wasEmpty }()

	removeEphemeral = func(e paths.Dirs, unlock func(), r daemon.Reporter) error {
		emptied = append(emptied, e.State)

		return wasEmpty(e, unlock, r)
	}

	mgr := &removing{fakeManager: fakeManager{d: d}}
	standInService(t, mgr)
	recordAccounts(t)

	out, errOut, code := capture(t, "uninstall", "--yes")
	if code != ExitOK {
		t.Fatalf("uninstall beside ephemeral roots not as conflux makes one exited %d, want %d:\n%s%s", code, ExitOK,
			out, errOut)
	}

	for _, root := range []string{shared, open, link, killed, readable} {
		if _, err := os.Lstat(root); !errors.Is(err, fs.ErrNotExist) || !strings.Contains(out, "  "+root+"\n") {
			t.Errorf("uninstall left %s, or did not say it removed it (Lstat: %v):\n%s", root, err, out)
		}
	}

	if !slices.Equal(emptied, []string{killed, readable}) {
		t.Errorf("uninstall took the lock of %q, want only the killed runs' roots, %q", emptied, []string{killed, readable})
	}

	if b, err := os.ReadFile(kept); err != nil || string(b) != "not conflux's" {
		t.Errorf("where a link at an ephemeral root's name led lost what is in it: %q, %v", b, err)
	}
}

// TestUninstallListsOnlyWhatIsGone: uninstall lists a root, or an ephemeral run's, as removed only
// where it is gone: not one it could not empty -- a folder in it whose mode lets its owner remove
// nothing, or a killed run's that would not empty -- which it names in the failure instead, exit 1.
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

	killed := filepath.Join(t.TempDir(), "conflux-ephemeral")
	if err := os.Mkdir(killed, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(killed, "serve.lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	defer func(was func() []string) { ephemeralCandidates = was }(ephemeralCandidates)
	ephemeralCandidates = func() []string { return []string{killed} }

	errStuck := errors.New("the killed run's root would not empty")

	wasEmpty := removeEphemeral
	defer func() { removeEphemeral = wasEmpty }()

	removeEphemeral = func(_ paths.Dirs, unlock func(), _ daemon.Reporter) error {
		unlock()

		return errStuck
	}

	standInService(t, &fakeManager{d: d})
	recordAccounts(t)

	out, errOut, code := capture(t, "uninstall", "--yes")
	if code != ExitError || !strings.Contains(errOut, stuck) || !strings.Contains(errOut, errStuck.Error()) {
		t.Errorf("uninstall of roots it could not empty exited %d, want %d naming why:\n%s%s", code, ExitError, out,
			errOut)
	}

	for _, root := range []string{d.State, killed} {
		if _, err := os.Lstat(root); err != nil || strings.Contains(out, "  "+root+"\n") {
			t.Errorf("uninstall listed %s, which is still there, as removed (Lstat: %v):\n%s", root, err, out)
		}
	}
}

// TestUninstallListsNoRootItFailedToRemove: a root, or an ephemeral run's that it removes reading
// nothing in it, that uninstall found something at the name of but could not remove is not listed as
// removed, whoever runs it: the failure names why instead, exit 1.
func TestUninstallListsNoRootItFailedToRemove(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	d := configured(t)

	// An ephemeral root the readers' check refuses, which uninstall removes reading nothing in it.
	candidate := filepath.Join(t.TempDir(), "conflux-ephemeral")
	if err := os.Mkdir(candidate, 0o700); err != nil {
		t.Fatal(err)
	}

	defer func(was func() []string) { ephemeralCandidates = was }(ephemeralCandidates)
	ephemeralCandidates = func() []string { return []string{candidate} }

	defer func(was func(string) error) { foreignRoot = was }(foreignRoot)
	foreignRoot = func(string) error { return errors.New("holds what another account could have put there") }

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

	for _, root := range []string{candidate, d.State} {
		if !slices.Contains(asked, root) || strings.Contains(out, "  "+root+"\n") {
			t.Errorf("uninstall listed %s, which it could not remove, as removed, or did not remove it (asked %q):\n%s",
				root, asked, out)
		}
	}
}
