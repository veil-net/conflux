//go:build !windows

package paths

import (
	"errors"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
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

// TestEnsureAllMakesItsRootInAStickyConfluxDir: a CONFLUX_DIR that is a sticky directory every account
// may add to, as /tmp is, passes parents' rule, since nobody may move what is not theirs in it, and
// conflux makes its root afresh inside it.
func TestEnsureAllMakesItsRootInAStickyConfluxDir(t *testing.T) {
	sticky := t.TempDir()
	if err := os.Chmod(sticky, 0o777|os.ModeSticky); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONFLUX_DIR", sticky)

	if err := Default().EnsureAll(); err != nil {
		t.Fatalf("EnsureAll(a sticky CONFLUX_DIR) = %v", err)
	}

	if fi, err := os.Lstat(filepath.Join(sticky, ".conflux")); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Errorf("the root in a sticky CONFLUX_DIR is %v (%v), want a directory at 0700", fi, err)
	}

	if fi, err := os.Lstat(sticky); err != nil || fi.Mode()&os.ModeSticky == 0 || fi.Mode().Perm() != 0o777 {
		t.Errorf("the sticky CONFLUX_DIR changed: %v (%v)", fi, err)
	}
}

// TestMakeRootJudgesTheWayBeforeItMakesAnything: a CONFLUX_DIR not made yet, reached through a link
// into a directory every account may write, is refused for that directory before anything is made
// on the way to it: making the root by its name would follow the link and make it there, where
// whoever may write the directory could have put a link of their own instead.
func TestMakeRootJudgesTheWayBeforeItMakesAnything(t *testing.T) {
	open := t.TempDir()
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}

	if err := os.Mkdir(filepath.Join(open, "real"), 0o700); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(t.TempDir(), "made")
	if err := os.Symlink(filepath.Join(open, "real"), link); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONFLUX_DIR", filepath.Join(link, "conflux"))

	if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), "inside "+open) {
		t.Errorf("EnsureAll(a CONFLUX_DIR through a link into a directory every account may write) = %v, want a "+
			"refusal naming %s", err, open)
	}

	if _, err := os.Lstat(filepath.Join(open, "real", "conflux")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("EnsureAll made the root where the link it refused leads (%v)", err)
	}
}

// TestALinkLeadingNowhereIsNoWayToMake: a CONFLUX_DIR reached through a link to a directory that is
// not there is no way conflux can make, nor a root that is not there: making it by its name would
// make what the link names, wherever that is. The walk refuses the link, naming it, with nothing made
// where it leads, and the readers' check refuses it the same, rather than take it for nothing
// installed.
func TestALinkLeadingNowhereIsNoWayToMake(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

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
// one is made and passes the readers' check, and the directory is judged as any other: once others
// may write it, Check refuses it, naming it.
func TestAWayThroughADirectoryThisAccountMaySearchAlone(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

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

	if err := Default().Check(); err == nil || !strings.Contains(err.Error(), "inside "+shut+", which anybody may write") {
		t.Errorf("Check(a CONFLUX_DIR under a 0333 directory of this account's) = %v, want a refusal naming it", err)
	}
}

// TestMakeRootJudgesWhatIsPlantedWhileItJudges: a name not there as the way to a root is judged may
// be there by the time conflux makes it, made by whoever may make a name in the directory -- its own
// group of one, here, whose answer is asked as the directory is judged, and plants a link there into a
// directory every account may write. The way is walked as it is judged, each name looked up only once
// the directory it is in is judged, so the link is met, judged and followed, and the directory it
// leads into refused, naming it, with nothing made there: not taken for the directory the root goes
// in, looked up by its name once the way was judged.
func TestMakeRootJudgesWhatIsPlantedWhileItJudges(t *testing.T) {
	me, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}

	open, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	if err := os.Mkdir(filepath.Join(open, "real"), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}

	var made string

	parent := groupWritableParent(t, func(bool) ([]string, error) {
		if _, err := os.Lstat(made); errors.Is(err, fs.ErrNotExist) {
			if err := os.Symlink(filepath.Join(open, "real"), made); err != nil {
				t.Fatal(err)
			}
		}

		return []string{me.Username}, nil
	})

	made = filepath.Join(parent, "made")
	t.Setenv("CONFLUX_DIR", filepath.Join(made, "conflux"))

	root := Default().State

	if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), root+" is inside "+open+
		", which anybody may write") {
		t.Errorf("EnsureAll, with a link into %s planted as the way was judged, = %v, want a refusal naming it", open, err)
	}

	if _, err := os.Lstat(filepath.Join(open, "real", "conflux")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("EnsureAll made the root where the link planted as the way was judged leads (%v)", err)
	}
}

// TestMakeRootGoesIntoNoNameTakenMeanwhile: the way to a root is walked from /, each directory judged
// before a name is looked up in it, and the directories missing -- made, and the CONFLUX_DIR in it -- are
// made each in the one held before it and gone into without following anything, each judged before
// anything is made in it, so what somebody else makes at a name meanwhile -- in /tmp, anybody may --
// answers for nothing it was not judged for. Planted at each name the walk looks up, and at each it makes
// or goes into: a link is followed and judged where the walk meets it, and refused, naming it, where it
// was made once conflux was making the name; a directory every account may write is refused, naming it,
// with nothing made in it -- by the walk where it is looked up, and by makeWay where it is made or gone
// into; and one of this account's own, as a conflux making the same root at once makes, is gone into.
// Planted at the root's own name as it is looked up, a link and a directory every account may write are
// removed as themselves and the root made afresh, and one of this account's own is the root. Nothing is
// made where a link leads.
func TestMakeRootGoesIntoNoNameTakenMeanwhile(t *testing.T) {
	was := looking
	t.Cleanup(func() { looking = was })

	// fresh is a base to make made/conflux/.conflux in, with CONFLUX_DIR set to made/conflux.
	fresh := func(t *testing.T) (step, dir, root string) {
		base, err := filepath.EvalSymlinks(t.TempDir()) // under /private/var on macOS
		if err != nil {
			t.Fatal(err)
		}

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
			// refused is the refusal for the plant by its phase: the path it names (the directory every
			// account may write, or the link), and why; "" where the root is made.
			refused func(step, dir, root, open string) []string
		}{
			{"a link into a directory every account may write", func(t *testing.T, at string) string {
				open, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}

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

				return []string{root + " is inside " + open + ", which anybody may write", made(step), made(step),
					made(dir), made(dir), ""}
			}},
			{"a directory every account may write", func(t *testing.T, at string) string {
				if err := os.Mkdir(at, 0o700); err != nil {
					t.Fatal(err)
				}

				if err := os.Chmod(at, 0o777); err != nil {
					t.Fatal(err)
				}

				return ""
			}, func(step, dir, root, _ string) []string {
				inside := func(at string) string { return root + " is inside " + at + ", which anybody may write" }

				return []string{inside(step), inside(step), inside(step), inside(dir), inside(dir), ""}
			}},
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
				case want == "" && (lmode(t, root) != os.ModeDir|0o700):
					t.Errorf("EnsureAll left the root %v, with %s planted at %s as it was %s, want a directory at 0700",
						lmode(t, root), c.name, at, phase)
				case want != "" && (err == nil || !strings.Contains(err.Error(), want)):
					t.Errorf("EnsureAll, with %s planted at %s as it was %s, = %v, want %q", c.name, at, phase, err,
						want)
				}

				if open != "" {
					entries, err := os.ReadDir(filepath.Join(open, "real"))
					if err != nil || len(entries) != 0 {
						t.Errorf("EnsureAll made %v where the link planted at %s leads (%v)", entries, at, err)
					}
				}

				// Refused at made, nothing is made in it.
				if at == step && c.refused(step, dir, root, open)[i] != "" && open == "" {
					if entries, err := os.ReadDir(step); err != nil || len(entries) != 0 {
						t.Errorf("EnsureAll made %v in %s, refused as it was %s (%v)", entries, step, phase, err)
					}
				}
			})
		}
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
