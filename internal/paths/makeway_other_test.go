//go:build !windows

package paths

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestEnsureAllLeavesTheConfluxDirAsItWas: a CONFLUX_DIR that is a folder of the user's, holding a
// bin/, a .ssh/ and a file, is never changed: conflux keeps everything in .conflux inside it, and what
// the folder held before is as it was, its mode included.
func TestEnsureAllLeavesTheConfluxDirAsItWas(t *testing.T) {
	home := t.TempDir()

	for p, mode := range map[string]os.FileMode{
		filepath.Join(home, "bin", "backup.sh"): 0o755,
		filepath.Join(home, ".ssh", "id"):       0o600,
		filepath.Join(home, "notes.txt"):        0o644,
	} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(p, []byte("the user's"), mode); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.Chmod(home, 0o755); err != nil {
		t.Fatal(err)
	}

	before := tree(t, home)

	t.Setenv("CONFLUX_DIR", home)

	d := Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatalf("EnsureAll(a CONFLUX_DIR of the user's) = %v", err)
	}

	if want := filepath.Join(home, ".conflux"); d.State != want || d.Config != want {
		t.Errorf("a CONFLUX_DIR's root is %s, want %s", d.State, want)
	}

	after := tree(t, home)
	delete(after, ".conflux")

	for p, was := range before {
		if after[p] != was {
			t.Errorf("%s was %s, and is %s once conflux made its roots", p, was, after[p])
		}
	}

	if len(after) != len(before) {
		t.Errorf("the CONFLUX_DIR holds %v, want what it held, %v, and .conflux", after, before)
	}
}

// tree is each path within dir, its own "." among them, with its mode, and what a file holds.
func tree(t *testing.T, dir string) map[string]string {
	t.Helper()

	found := map[string]string{}

	if err := filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, _ := filepath.Rel(dir, p)
		if strings.HasPrefix(rel, ".conflux") {
			found[".conflux"] = "made"

			return fs.SkipDir
		}

		fi, err := e.Info()
		if err != nil {
			return err
		}

		found[rel] = fi.Mode().String()

		if fi.Mode().IsRegular() {
			b, _ := os.ReadFile(p)
			found[rel] += " " + string(b)
		}

		return nil
	}); err != nil {
		t.Fatal(err)
	}

	return found
}

// TestEnsureAllRemakesWhatIsNotItsOwn: what is at the root's name and is not as conflux makes a root --
// a link, a file, a folder of its own that others may write -- is removed as itself and the root made
// afresh, 0700: where a link led is never touched, and what the wide folder held goes with it.
func TestEnsureAllRemakesWhatIsNotItsOwn(t *testing.T) {
	elsewhere := t.TempDir()

	kept := filepath.Join(elsewhere, "kept")
	if err := os.WriteFile(kept, []byte("not conflux's"), 0o600); err != nil {
		t.Fatal(err)
	}

	for name, plant := range map[string]func(root string) error{
		"a link": func(root string) error { return os.Symlink(elsewhere, root) },
		"a file": func(root string) error { return os.WriteFile(root, []byte("a file"), 0o600) },
		"a wide folder": func(root string) error {
			if err := os.Mkdir(root, 0o777); err != nil {
				return err
			}

			if err := os.Chmod(root, 0o777); err != nil {
				return err
			}

			return os.WriteFile(filepath.Join(root, "planted"), []byte("anybody's"), 0o600)
		},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("CONFLUX_DIR", dir)

			root := filepath.Join(dir, ".conflux")
			if err := plant(root); err != nil {
				t.Fatal(err)
			}

			d := Default()
			if err := d.EnsureAll(); err != nil {
				t.Fatalf("EnsureAll(%s at the root's name) = %v", name, err)
			}

			fi, err := os.Lstat(root)
			if err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
				t.Fatalf("the root is %v (%v), want a directory at 0700", fi, err)
			}

			if _, err := os.Lstat(filepath.Join(root, "planted")); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("the root made afresh holds what the wide folder held (Lstat: %v)", err)
			}

			if b, err := os.ReadFile(kept); err != nil || string(b) != "not conflux's" {
				t.Errorf("where a link at the root's name led lost what is in it: %q, %v", b, err)
			}
		})
	}
}

// TestEnsureAllRemakesAFolderOfItsOwnNotAsConfluxMakesIt: each folder conflux keeps in a root -- run/,
// logs/ where the platform writes a log, bin/ and anchor.root/ -- is judged as the root is: what is at its
// name and is not as conflux makes a folder of its own -- a folder others may write, a link, a file -- is
// removed as itself, whatever it held, and the folder made afresh at 0700, where the link led untouched;
// one that is as conflux makes it is kept with what it holds, and the run and log directories are made
// at 0700 where they are not there.
func TestEnsureAllRemakesAFolderOfItsOwnNotAsConfluxMakesIt(t *testing.T) {
	elsewhere := t.TempDir()

	kept := filepath.Join(elsewhere, "kept")
	if err := os.WriteFile(kept, []byte("not conflux's"), 0o600); err != nil {
		t.Fatal(err)
	}

	wide := func(dir string) error {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return err
		}

		if err := os.WriteFile(filepath.Join(dir, "planted"), []byte("anybody's"), 0o600); err != nil {
			return err
		}

		return os.Chmod(dir, 0o777)
	}

	plants := map[string]func(string) error{
		"a wide folder": wide,
		"a link":        func(dir string) error { return os.Symlink(elsewhere, dir) },
		"a file":        func(dir string) error { return os.WriteFile(dir, []byte("a file"), 0o600) },
	}

	t.Setenv("CONFLUX_DIR", t.TempDir())

	d := Default()

	folders := []string{d.Run, d.Libexec(), d.RootAnchorDir()}
	if d.Log != "" {
		folders = append(folders, d.Log)
	}

	for _, dir := range folders {
		for name, plant := range plants {
			t.Run(filepath.Base(dir)+"/"+name, func(t *testing.T) {
				if err := os.RemoveAll(d.State); err != nil {
					t.Fatal(err)
				}

				if err := d.EnsureAll(); err != nil {
					t.Fatal(err)
				}

				if err := os.RemoveAll(dir); err != nil {
					t.Fatal(err)
				}

				if err := plant(dir); err != nil {
					t.Fatal(err)
				}

				if err := d.EnsureAll(); err != nil {
					t.Fatalf("EnsureAll(%s at %s) = %v", name, dir, err)
				}

				if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
					t.Errorf("%s is %v (%v), want a directory at 0700", dir, modeOf(fi), err)
				}

				if _, err := os.Lstat(filepath.Join(dir, "planted")); !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("%s made afresh holds what the wide folder held (Lstat: %v)", dir, err)
				}

				if b, err := os.ReadFile(kept); err != nil || string(b) != "not conflux's" {
					t.Errorf("where a link at %s led lost what is in it: %q, %v", dir, b, err)
				}
			})
		}
	}

	t.Run("as conflux makes them", func(t *testing.T) {
		if err := os.RemoveAll(d.State); err != nil {
			t.Fatal(err)
		}

		if err := d.EnsureAll(); err != nil {
			t.Fatal(err)
		}

		for _, dir := range []string{d.Run, d.Log} {
			if fi, err := os.Lstat(dir); dir != "" && (err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700) {
				t.Errorf("%s is %v (%v), want a directory made at 0700", dir, modeOf(fi), err)
			}
		}

		for _, dir := range folders {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}

			if err := os.WriteFile(filepath.Join(dir, "kept"), []byte("conflux's"), 0o600); err != nil {
				t.Fatal(err)
			}
		}

		if err := d.EnsureAll(); err != nil {
			t.Fatal(err)
		}

		for _, dir := range folders {
			if b, err := os.ReadFile(filepath.Join(dir, "kept")); err != nil || string(b) != "conflux's" {
				t.Errorf("EnsureAll changed %s, as conflux makes it: %q, %v", dir, b, err)
			}
		}
	})
}

// modeOf is fi's mode, or nothing where there is no fi.
func modeOf(fi os.FileInfo) any {
	if fi == nil {
		return nil
	}

	return fi.Mode()
}

// TestEnsureAllSaysWhyARootItCannotRemoveIsNotItsOwn: a root not as conflux makes one that EnsureAll
// cannot remove, to make it afresh, is refused saying why it is not conflux's as well as why the removal
// failed: here a folder every account may write, holding a folder whose mode lets its owner remove
// nothing in it.
func TestEnsureAllSaysWhyARootItCannotRemoveIsNotItsOwn(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a folder whose mode lets its owner remove nothing in it holds nothing back from root")
	}

	t.Setenv("CONFLUX_DIR", t.TempDir())

	root := Default().State
	stuck := filepath.Join(root, "stuck")

	if err := os.MkdirAll(stuck, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(stuck, "kept"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	for p, mode := range map[string]os.FileMode{stuck: 0o500, root: 0o777} {
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
	}

	t.Cleanup(func() { _ = os.Chmod(stuck, 0o700) })

	err := Default().EnsureAll()
	if err == nil || !strings.Contains(err.Error(), root+" is not as conflux makes a folder of its own (anybody may write") ||
		!strings.Contains(err.Error(), "permission denied") {
		t.Errorf("EnsureAll(a root every account may write that it cannot remove) = %v, want a refusal saying why "+
			"it is not conflux's and why it could not be removed", err)
	}
}

// TestEnsureAllJudgesNoFolderAboveARoot: a CONFLUX_DIR, and every folder above its root, is the user's
// choice, never judged and never changed: one every account may write, sticky or not, one under a
// parent anybody or another account's group may write, and one reached through a link, or a chain of
// links, into a directory anybody may write, each has its root made, 0700, where it leads, and passes the
// readers' check and uninstall's walk, with no group asked who it lets in and the folders above left as
// they were.
func TestEnsureAllJudgesNoFolderAboveARoot(t *testing.T) {
	was := groups
	t.Cleanup(func() { groups = was })

	groups = groupsFunc(func(name, gid string) ([]string, error) {
		t.Errorf("who group %s (%s) lets in was asked, for a folder above a root", name, gid)

		return []string{"mallory"}, nil
	})

	for _, c := range []struct {
		name string
		// plant makes what CONFLUX_DIR names, under base, and is it and the folder whose mode must stay.
		plant func(t *testing.T, base string) (dir, open string)
	}{
		{"the CONFLUX_DIR every account may write", func(t *testing.T, base string) (string, string) {
			return base, base
		}},
		{"the CONFLUX_DIR every account may write, sticky", func(t *testing.T, base string) (string, string) {
			return base, base
		}},
		{"a parent every account may write", func(t *testing.T, base string) (string, string) {
			return filepath.Join(base, "conflux"), base
		}},
		{"a parent its group, with another account in it, may write", func(t *testing.T, base string) (string, string) {
			return filepath.Join(base, "conflux"), base
		}},
		{"a link into a directory every account may write", func(t *testing.T, base string) (string, string) {
			if err := os.Mkdir(filepath.Join(base, "real"), 0o700); err != nil {
				t.Fatal(err)
			}

			link := filepath.Join(realTempDir(t), "link")
			if err := os.Symlink(filepath.Join(base, "real"), link); err != nil {
				t.Fatal(err)
			}

			return filepath.Join(link, "conflux"), base
		}},
		{"a chain of links through a directory every account may write", func(t *testing.T, base string) (string, string) {
			real := filepath.Join(realTempDir(t), "real")
			if err := os.Mkdir(real, 0o700); err != nil {
				t.Fatal(err)
			}

			if err := os.Symlink(real, filepath.Join(base, "l2")); err != nil {
				t.Fatal(err)
			}

			l1 := filepath.Join(realTempDir(t), "l1")
			if err := os.Symlink(filepath.Join(base, "l2"), l1); err != nil {
				t.Fatal(err)
			}

			return l1, base
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			base := realTempDir(t)
			dir, open := c.plant(t, base)

			perm := os.FileMode(0o777)
			switch {
			case strings.HasSuffix(c.name, "sticky"):
				perm |= os.ModeSticky
			case strings.Contains(c.name, "its group"):
				perm = 0o770
			}

			if err := os.Chmod(open, perm); err != nil {
				t.Fatal(err)
			}

			before := lmode(t, open)

			t.Setenv("CONFLUX_DIR", dir)

			d := Default()
			if err := d.EnsureAll(); err != nil {
				t.Fatalf("EnsureAll(%s) = %v", c.name, err)
			}

			if got := mode(t, d.State); got != 0o700 {
				t.Errorf("the root under %s is %v, want 0700", c.name, got)
			}

			if err := d.Check(); err != nil {
				t.Errorf("Check(a root under %s) = %v", c.name, err)
			}

			if err := d.WalkWays(); err != nil {
				t.Errorf("WalkWays(a root under %s) = %v", c.name, err)
			}

			if got := lmode(t, open); got != before {
				t.Errorf("%s became %v, was %v: a folder above a root is never changed", open, got, before)
			}
		})
	}
}

// TestALinkLeadingNowhereIsNoWayToMake: a CONFLUX_DIR reached through a link to a directory that is
// not there is no way conflux can make, nor a root that is not there: making it by its name would
// make what the link names, wherever that is. The walk refuses the link, naming it, with nothing made
// where it leads, and the readers' check refuses it the same, rather than take it for nothing
// installed.
func TestALinkLeadingNowhereIsNoWayToMake(t *testing.T) {
	base := realTempDir(t)

	nowhere, link := filepath.Join(base, "nowhere"), filepath.Join(base, "link")
	if err := os.Symlink(filepath.Join(nowhere, "deeper"), link); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONFLUX_DIR", filepath.Join(link, "conflux"))

	refused := link + " is a link conflux cannot follow"

	if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), refused) {
		t.Errorf("EnsureAll(a CONFLUX_DIR through a link to a directory not there) = %v, want %q", err, refused)
	}

	if _, err := os.Lstat(nowhere); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("EnsureAll made %s, where the link it refused leads (%v)", nowhere, err)
	}

	if err := Default().Check(); err == nil || errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), refused) {
		t.Errorf("Check(a CONFLUX_DIR through a link to a directory not there) = %v, want %q, not nothing installed",
			err, refused)
	}
}

// TestAWayThroughADirectoryThisAccountMaySearchAlone: a directory of this account's that it may search
// and not read, 0311, cannot be opened to read, which is how the walk holds a directory on macOS and
// the BSDs, so there it is held by its name in the directory held before it (lookUp), and the names
// after it are looked up through that name; Linux opens it as a path. Either way a CONFLUX_DIR under
// one is made and passes the readers' check, and, as every folder above a root, is not judged: once
// others may write it, Check still takes the root.
func TestAWayThroughADirectoryThisAccountMaySearchAlone(t *testing.T) {
	base := realTempDir(t)

	shut := filepath.Join(base, "shut")
	if err := os.Mkdir(shut, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(shut, 0o311); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { os.Chmod(shut, 0o700) }) // for TempDir to list it, to remove it

	t.Setenv("CONFLUX_DIR", filepath.Join(shut, "conflux"))

	if err := Default().EnsureAll(); err != nil {
		t.Fatalf("EnsureAll(a CONFLUX_DIR under a 0311 directory of this account's) = %v", err)
	}

	if err := Default().Check(); err != nil {
		t.Errorf("Check(a CONFLUX_DIR under a 0311 directory of this account's) = %v", err)
	}

	if err := os.Chmod(shut, 0o333); err != nil {
		t.Fatal(err)
	}

	if err := Default().Check(); err != nil {
		t.Errorf("Check(a CONFLUX_DIR under a 0333 directory of this account's) = %v", err)
	}
}

// TestMakeRootGoesIntoNoNameTakenMeanwhile: the way to a root is walked from /, and the directories
// missing -- made, and the CONFLUX_DIR in it -- are made each in the one held before it and gone into
// without following anything, so what somebody else makes at a name meanwhile -- in /tmp, anybody may --
// is never followed where conflux made the name. Planted at each name the walk looks up, and at each it
// makes or goes into: a link is followed where the walk meets it, as any link on the way is, and refused,
// naming it, where it was made once conflux was making the name, with nothing made where it leads; a
// directory, every account's to write or this account's own, as a conflux making the same root at once
// makes, is gone into, unjudged, as every folder above a root is. Planted at the root's own name as it is
// looked up, a link and a directory every account may write are removed as themselves, what the
// directory held with it, and the root made afresh, and one of this account's own is the root.
func TestMakeRootGoesIntoNoNameTakenMeanwhile(t *testing.T) {
	was := looking
	t.Cleanup(func() { looking = was })

	// fresh is a base to make made/conflux/.conflux in, with CONFLUX_DIR set to made/conflux.
	fresh := func(t *testing.T) (step, dir, root string) {
		base := realTempDir(t) // under /private/var on macOS

		step = filepath.Join(base, "made")
		dir = filepath.Join(step, "conflux")
		t.Setenv("CONFLUX_DIR", dir)

		return step, dir, Default().State
	}

	// Where looking is called on a run with nothing planted, from the walk's lookup of made on: made
	// looked up, made made, made gone into, conflux made, conflux gone into, the root looked up.
	step, dir, root := fresh(t)

	var calls []string

	looking = func(p string) { calls = append(calls, p) }

	if err := Default().EnsureAll(); err != nil {
		t.Fatal(err)
	}

	first := slices.Index(calls, step)
	if first < 0 || len(calls) < first+6 || !slices.Equal(calls[first:first+6], []string{step, step, step, dir, dir,
		root}) {
		t.Fatalf("looking was called with %q, want made looked up, made and gone into, then conflux, then the root",
			calls)
	}

	phases := []string{"looked up", "made", "gone into", "made, the CONFLUX_DIR", "gone into, the CONFLUX_DIR",
		"looked up, the root"}

	for i, phase := range phases {
		for _, c := range []struct {
			name  string
			plant func(t *testing.T, at string) (open string)
			// refused is the refusal for the plant by its phase: the link it names, and why; "" where the
			// root is made.
			refused func(step, dir, root, open string) []string
		}{
			{"a link into a directory every account may write", func(t *testing.T, at string) string {
				open := realTempDir(t)

				if err := os.Mkdir(filepath.Join(open, "real"), 0o700); err != nil {
					t.Fatal(err)
				}

				if err := os.Chmod(open, 0o777); err != nil {
					t.Fatal(err)
				}

				if err := os.Symlink(filepath.Join(open, "real"), at); err != nil {
					t.Fatal(err)
				}

				return open
			}, func(step, dir, root, open string) []string {
				made := func(at string) string {
					return at + ", a link, was made while conflux made the way to " + root
				}

				return []string{"", made(step), made(step), made(dir), made(dir), ""}
			}},
			{"a directory every account may write", func(t *testing.T, at string) string {
				if err := os.Mkdir(at, 0o700); err != nil {
					t.Fatal(err)
				}

				// At the root's name, which is made afresh, with something in it to go with it.
				if filepath.Base(at) == DirName {
					if err := os.WriteFile(filepath.Join(at, "planted"), []byte("anybody's"), 0o600); err != nil {
						t.Fatal(err)
					}
				}

				if err := os.Chmod(at, 0o777); err != nil {
					t.Fatal(err)
				}

				return ""
			}, func(string, string, string, string) []string { return make([]string, len(phases)) }},
			{"a directory of this account's own", func(t *testing.T, at string) string {
				if err := os.Mkdir(at, 0o700); err != nil {
					t.Fatal(err)
				}

				return ""
			}, func(string, string, string, string) []string { return make([]string, len(phases)) }},
		} {
			t.Run(c.name+", "+phase, func(t *testing.T) {
				step, dir, root := fresh(t)
				at := []string{step, step, step, dir, dir, root}[i]

				var open string

				n := 0
				looking = func(p string) {
					if p != at {
						return
					}

					if n++; n == []int{1, 2, 3, 1, 2, 1}[i] {
						// What conflux made is there to be gone into: what is planted takes its place.
						if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
							t.Fatal(err)
						}

						open = c.plant(t, p)
					}
				}

				err := Default().EnsureAll()

				switch want := c.refused(step, dir, root, open)[i]; {
				case want == "" && err != nil:
					t.Errorf("EnsureAll, with %s planted at %s as it was %s, = %v", c.name, at, phase, err)
				case want == "" && mode(t, root) != 0o700:
					t.Errorf("EnsureAll left the root %v, with %s planted at %s as it was %s, want a directory at 0700",
						lmode(t, root), c.name, at, phase)
				case want == "" && at == root:
					if _, err := os.Lstat(filepath.Join(root, "planted")); !errors.Is(err, fs.ErrNotExist) {
						t.Errorf("the root EnsureAll made afresh, with %s planted at it, holds what that held (Lstat: %v)",
							c.name, err)
					}
				case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
					t.Errorf("EnsureAll, with %s planted at %s as it was %s, = %v, want %q", c.name, at, phase, err,
						want)
				}

				if open != "" && c.refused(step, dir, root, open)[i] != "" {
					entries, err := os.ReadDir(filepath.Join(open, "real"))
					if err != nil || len(entries) != 0 {
						t.Errorf("EnsureAll made %v where the link planted at %s leads (%v)", entries, at, err)
					}
				}
			})
		}
	}
}

// TestMakeRootGoesIntoNoLinkMadeOnceItIsMade: the root, once made, is looked up again in the folder it
// is in to be held, where nothing is followed: a link put at its name in the moment since is refused,
// naming it, and nothing is made where it leads.
func TestMakeRootGoesIntoNoLinkMadeOnceItIsMade(t *testing.T) {
	was := looking
	t.Cleanup(func() { looking = was })

	t.Setenv("CONFLUX_DIR", t.TempDir())

	root := Default().State
	elsewhere := t.TempDir()

	n := 0
	looking = func(p string) {
		if p != root {
			return
		}

		if n++; n == 2 {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}

			if err := os.Symlink(elsewhere, p); err != nil {
				t.Fatal(err)
			}
		}
	}

	if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), root+", a link, was made") {
		t.Errorf("EnsureAll, with a link put at the root's name once it was made, = %v, want a refusal naming it", err)
	}

	if entries, err := os.ReadDir(elsewhere); err != nil || len(entries) > 0 {
		t.Errorf("EnsureAll made %v where the link leads (%v)", entries, err)
	}
}

// lmode is what Lstat says of p's type and permissions.
func lmode(t *testing.T, p string) os.FileMode {
	t.Helper()

	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}

	return fi.Mode() & (os.ModeType | os.ModePerm)
}
