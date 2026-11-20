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
	root := filepath.Join(made, "conflux")
	t.Setenv("CONFLUX_DIR", root)

	if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), root+" is inside "+open+
		", which anybody may write") {
		t.Errorf("EnsureAll, with a link into %s planted as the way was judged, = %v, want a refusal naming it", open, err)
	}

	if _, err := os.Lstat(filepath.Join(open, "real", "conflux")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("EnsureAll made the root where the link planted as the way was judged leads (%v)", err)
	}
}

// TestMakeRootGoesIntoNoNameTakenMeanwhile: the way to a root is walked from /, each directory judged
// before a name is looked up in it, and the directories missing are made each in the one held before
// it and gone into without following anything, so what somebody else makes at a name meanwhile -- in
// /tmp, anybody may -- answers for nothing it was not judged for. Planted at each name the walk looks
// up, and at each it makes or goes into: a link is followed and judged where the walk meets it, and
// refused, naming it, where it was made once conflux was making the name; a directory every account
// may write is refused, naming it, before anything is made in it, but at the root's own name, which
// is the root, secure's to narrow; and one of this account's own, as a conflux making the same root
// at once makes, is gone into. Nothing is made where a link leads.
func TestMakeRootGoesIntoNoNameTakenMeanwhile(t *testing.T) {
	was := looking
	t.Cleanup(func() { looking = was })

	// fresh is a base to make made/conflux in, with CONFLUX_DIR set to it.
	fresh := func(t *testing.T) (step, root string) {
		base, err := filepath.EvalSymlinks(t.TempDir()) // under /private/var on macOS
		if err != nil {
			t.Fatal(err)
		}

		step = filepath.Join(base, "made")
		root = filepath.Join(step, "conflux")
		t.Setenv("CONFLUX_DIR", root)

		return step, root
	}

	// Where looking is called on a run with nothing planted, from the walk's lookup of made on:
	// made looked up, made made, made gone into, conflux made, conflux gone into.
	_, root := fresh(t)

	var calls []string

	looking = func(p string) { calls = append(calls, p) }

	if err := Default().EnsureAll(); err != nil {
		t.Fatal(err)
	}

	first := slices.Index(calls, filepath.Dir(root))
	if first < 0 || len(calls) < first+5 || !slices.Equal(calls[first:first+5], []string{filepath.Dir(root),
		filepath.Dir(root), filepath.Dir(root), root, root}) {
		t.Fatalf("looking was called with %q, want made looked up, made and gone into, then conflux", calls)
	}

	phases := []string{"looked up", "made", "gone into", "made, the root", "gone into, the root"}

	for i, phase := range phases {
		for _, c := range []struct {
			name  string
			plant func(t *testing.T, at string) (open string)
			// refused is the refusal for the plant at made, by its phase, and at conflux, its own: the
			// path it names (the directory every account may write, or the link), and why.
			refused func(step, root, open string) []string
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
			}, func(step, root, open string) []string {
				made := func(at string) string {
					return at + ", a link, was made while conflux made the way to " + root
				}

				return []string{
					root + " is inside " + open + ", which anybody may write",
					made(step), made(step), made(root), made(root),
				}
			}},
			{"a directory every account may write", func(t *testing.T, at string) string {
				if err := os.Mkdir(at, 0o700); err != nil {
					t.Fatal(err)
				}

				if err := os.Chmod(at, 0o777); err != nil {
					t.Fatal(err)
				}

				return ""
			}, func(step, root, _ string) []string {
				inside := root + " is inside " + step + ", which anybody may write"

				return []string{inside, inside, inside, "", ""}
			}},
			{"a directory of this account's own", func(t *testing.T, at string) string {
				if err := os.Mkdir(at, 0o700); err != nil {
					t.Fatal(err)
				}

				return ""
			}, func(string, string, string) []string { return make([]string, len(phases)) }},
		} {
			t.Run(c.name+", "+phase, func(t *testing.T) {
				step, root := fresh(t)
				at := []string{step, step, step, root, root}[i]

				var open string

				n := 0
				looking = func(p string) {
					if p != at {
						return
					}

					if n++; n == map[int]int{0: 1, 1: 2, 2: 3, 3: 1, 4: 2}[i] {
						// What conflux made is there to be gone into: what is planted takes its place.
						if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
							t.Fatal(err)
						}

						open = c.plant(t, p)
					}
				}

				err := Default().EnsureAll()

				switch want := c.refused(step, root, open)[i]; {
				case want == "" && err != nil:
					t.Errorf("EnsureAll, with %s planted at %s as it was %s, = %v", c.name, at, phase, err)
				case want == "" && mode(t, root) != 0o700:
					t.Errorf("EnsureAll left the root at %#o, with %s planted at %s as it was %s, want 0700",
						mode(t, root), c.name, at, phase)
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
			})
		}
	}
}
