//go:build !windows

package paths

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
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

// TestMakeRootGoesIntoNoNameTakenMeanwhile: the directories missing on the way to a root are made
// each through the one before, and gone into without following anything, so what somebody else
// makes at a name conflux is about to make -- in /tmp, anybody may -- answers for nothing: a link
// is refused, naming it, and nothing is made where it leads; a directory every account may write is
// refused, naming it, and nothing is made in it; one of this account's own, as a conflux making the
// same root at once makes, is gone into.
func TestMakeRootGoesIntoNoNameTakenMeanwhile(t *testing.T) {
	was := making
	t.Cleanup(func() { making = was })

	elsewhere := t.TempDir()

	for _, c := range []struct {
		name    string
		plant   func(at string) error
		refused string
	}{
		{"a link", func(at string) error { return os.Symlink(elsewhere, at) }, "a link"},
		{"a directory every account may write", func(at string) error {
			if err := os.Mkdir(at, 0o700); err != nil {
				return err
			}

			return os.Chmod(at, 0o777)
		}, "anybody may write"},
		{"a directory of this account's own", func(at string) error { return os.Mkdir(at, 0o700) }, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			base := t.TempDir()
			step := filepath.Join(base, "made")
			root := filepath.Join(step, "conflux")

			making = func(at string) {
				if at == step {
					if err := c.plant(at); err != nil {
						t.Fatal(err)
					}
				}
			}

			t.Setenv("CONFLUX_DIR", root)

			err := Default().EnsureAll()

			switch {
			case c.refused == "" && err != nil:
				t.Errorf("EnsureAll, with %s made at %s meanwhile, = %v", c.name, step, err)
			case c.refused != "" && (err == nil || !strings.Contains(err.Error(), step) ||
				!strings.Contains(err.Error(), c.refused)):
				t.Errorf("EnsureAll, with %s made at %s meanwhile, = %v, want a refusal naming it and %q", c.name, step,
					err, c.refused)
			}

			for _, made := range []string{filepath.Join(elsewhere, "conflux"), root} {
				if _, err := os.Lstat(made); c.refused != "" && !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("EnsureAll made %s, with %s made at %s meanwhile (%v)", made, c.name, step, err)
				}
			}
		})
	}
}
