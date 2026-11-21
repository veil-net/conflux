//go:build !windows

package paths

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestASharedDirectoryIsNoRoot: no root conflux narrows, fills or empties may be a directory others
// keep what is theirs in, whoever owns it: a CONFLUX_DIR that is a sticky directory of this account's,
// the directory the running conflux is in, or, where conflux does not run as root, the filesystem's
// root, is refused by EnsureAll, naming why, with its mode and what it holds as they were, and by
// JudgeWays as a shared root, not a way; so is one whose name is a link to the sticky directory, by
// EnsureAll. RemoveRoot refuses the sticky directory, removing nothing. A link to it holding what is
// another account's is refused by JudgeWays and RemoveRoot as a foreign root, the link left; one
// holding nothing else RemoveRoot removes as itself, leaving the directory as it was.
func TestASharedDirectoryIsNoRoot(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	shared := filepath.Join(base, "shared")
	if err := os.Mkdir(shared, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(shared, "theirs"), []byte("theirs"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(shared, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(base, "conflux")
	if err := os.Symlink(shared, link); err != nil {
		t.Fatal(err)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string]struct{ root, why string }{
		"a sticky directory":                      {shared, "a sticky directory"},
		"a link to a sticky directory":            {link, "a sticky directory"},
		"the directory the running conflux is in": {filepath.Dir(exe), "the directory the running conflux is in"},
	}
	if os.Geteuid() != 0 {
		cases["the filesystem's root"] = struct{ root, why string }{"/", "the filesystem's root"}
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv("CONFLUX_DIR", c.root)

			mode, held := asFound(t, c.root)

			switch err := Default().JudgeWays(); {
			case c.root == link && (!errors.Is(err, ErrForeignRoot) || !strings.Contains(err.Error(), "holds theirs")):
				t.Errorf("JudgeWays(a CONFLUX_DIR of %s) = %v, want a refusal of a foreign root naming theirs", name, err)
			case c.root != link && (!errors.Is(err, ErrSharedRoot) || errors.Is(err, ErrWayRefused) ||
				!strings.Contains(err.Error(), c.why)):
				t.Errorf("JudgeWays(a CONFLUX_DIR of %s) = %v, want a refusal of a shared root saying it is %s", name,
					err, c.why)
			}

			if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), c.why) {
				t.Errorf("EnsureAll(a CONFLUX_DIR of %s) = %v, want a refusal saying it is %s", name, err, c.why)
			}

			if m, h := asFound(t, c.root); m != mode || !slices.Equal(h, held) {
				t.Errorf("EnsureAll(a CONFLUX_DIR of %s) left it %v holding %q, want %v holding %q", name, m, h, mode,
					held)
			}
		})
	}

	t.Setenv("CONFLUX_DIR", shared)

	if gone, err := RemoveRoot(shared); gone || err == nil || !strings.Contains(err.Error(), "a sticky directory") {
		t.Errorf("RemoveRoot(a sticky directory) = %v, %v, want a refusal saying so", gone, err)
	}

	t.Setenv("CONFLUX_DIR", link)

	if gone, err := RemoveRoot(link); gone || err == nil || !strings.Contains(err.Error(), "holds theirs") {
		t.Errorf("RemoveRoot(a link to a sticky directory holding another's) = %v, %v, want a refusal naming it", gone,
			err)
	}

	if err := os.Remove(filepath.Join(shared, "theirs")); err != nil {
		t.Fatal(err)
	}

	if gone, err := RemoveRoot(link); !gone || err != nil {
		t.Errorf("RemoveRoot(a link to a sticky directory holding nothing else) = %v, %v, want the link removed", gone,
			err)
	}

	if m, h := asFound(t, shared); m != 0o777|os.ModeSticky|os.ModeDir || len(h) != 0 {
		t.Errorf("RemoveRoot left the sticky directory %v holding %q, want it as it was", m, h)
	}
}

// asFound is the mode of the directory dir leads to and the names it holds.
func asFound(t *testing.T, dir string) (os.FileMode, []string) {
	t.Helper()

	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}

	return fi.Mode(), names
}

// TestTheServicesOwnRootHoldsItsConflux: the directory the running conflux is in is no root, but where
// that conflux is the copy the boot service runs there -- the file at the copy's name, conflux, never
// followed -- whatever the root's mode: 0700, 0710 or widened to 0755. A conflux of another name there,
// or a link at the copy's name to the running one, is refused, and so is every directory above it.
func TestTheServicesOwnRootHoldsItsConflux(t *testing.T) {
	root := t.TempDir()

	for _, name := range []string{"conflux2", "real"} {
		if err := os.WriteFile(filepath.Join(root, name), nil, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.Link(filepath.Join(root, "conflux2"), filepath.Join(root, "conflux")); err != nil {
		t.Fatal(err)
	}

	link := t.TempDir()
	if err := os.Symlink("real", filepath.Join(link, "conflux")); err != nil {
		t.Fatal(err)
	}

	if err := os.Rename(filepath.Join(root, "real"), filepath.Join(link, "real")); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		root, exe string
		mode      os.FileMode
		ok        bool
	}{
		{root, "conflux", 0o700, true},
		{root, "conflux", 0o710, true},
		{root, "conflux", 0o755, true},
		{root, "conflux2", 0o700, true}, // a second name of the copy is the copy
		{link, "real", 0o700, false},
	} {
		if err := os.Chmod(c.root, c.mode); err != nil {
			t.Fatal(err)
		}

		ps := systemPlacesOf(t.TempDir(), filepath.Join(c.root, c.exe), Dirs{})

		if err := sharedRootIn(ps, c.root, held(t, c.root)); (err == nil) != c.ok {
			t.Errorf("sharedRoot(the root %s runs from, at %v) = %v, want it taken %v", c.exe, c.mode, err, c.ok)
		}

		if err := sharedRootIn(ps, filepath.Dir(c.root), held(t, filepath.Dir(c.root))); err == nil {
			t.Errorf("sharedRoot(the directory above the root %s runs from) = nil, want a refusal", c.exe)
		}
	}

	other := filepath.Join(t.TempDir(), "conflux")
	if err := os.WriteFile(other, nil, 0o700); err != nil {
		t.Fatal(err)
	}

	ps := systemPlacesOf(t.TempDir(), filepath.Join(filepath.Dir(other), "other"), Dirs{})

	if err := sharedRootIn(ps, filepath.Dir(other), held(t, filepath.Dir(other))); err == nil {
		t.Errorf("sharedRoot(the root a conflux of another name runs from, a conflux beside it) = nil, want a refusal")
	}
}

// TestTheServiceNarrowsItsOwnWidenedRoot: the boot service runs the copy of conflux in its state root,
// and that root is the directory the running conflux is in, which is no root but for the service's
// own: so a state root found widened to 0755 is taken, whatever its mode, and EnsureAll narrows it to
// 0700, as it narrows any root of conflux's, rather than refuse it at every start.
func TestTheServiceNarrowsItsOwnWidenedRoot(t *testing.T) {
	root := filepath.Join(t.TempDir(), "conflux")
	t.Setenv("CONFLUX_DIR", root)

	d := Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(d.ServiceExecutable(), []byte("conflux"), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}

	was := systemDirs
	t.Cleanup(func() { systemDirs = was })

	systemDirs = func() systemPlaces { return systemPlacesOf("/", d.ServiceExecutable(), platformDirs()) }

	if err := d.EnsureAll(); err != nil {
		t.Fatalf("EnsureAll(the service's own root at 0755, run as its copy) = %v, want it taken", err)
	}

	if fi, err := os.Stat(root); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("the service's own root once EnsureAll took it = %v, %v, want it narrowed to 0700", fi.Mode(), err)
	}
}

// held is the directory dir held open as a walk holds one (opened), let go of when t ends.
func held(t *testing.T, dir string) step {
	t.Helper()

	s, err := opened(unix.AT_FDCWD, dir)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(s.close)

	return s
}
