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
			inData(t, dir)

			root := filepath.Join(dir, DirName)
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

	inData(t, t.TempDir())

	d := Default()

	folders := []string{d.RunDir(), d.Libexec(), d.RootAnchorDir()}
	if d.LogDir() != "" {
		folders = append(folders, d.LogDir())
	}

	for _, dir := range folders {
		for name, plant := range plants {
			t.Run(filepath.Base(dir)+"/"+name, func(t *testing.T) {
				if err := os.RemoveAll(d.Root); err != nil {
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
		if err := os.RemoveAll(d.Root); err != nil {
			t.Fatal(err)
		}

		if err := d.EnsureAll(); err != nil {
			t.Fatal(err)
		}

		for _, dir := range []string{d.RunDir(), d.LogDir()} {
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

	inData(t, t.TempDir())

	root := Default().Root
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

// TestEnsureAllJudgesNoFolderAboveARoot: the folder the root is in, and every folder above it, is the
// system's, never judged and never changed: one every account may write, sticky or not, and one under a
// parent anybody or another account's group may write, each has its root made, 0700, and passes the
// readers' check, with the folders above left as they were.
func TestEnsureAllJudgesNoFolderAboveARoot(t *testing.T) {
	for _, c := range []struct {
		name string
		// plant makes the folder the root is in, under base, and is it and the folder whose mode must stay.
		plant func(t *testing.T, base string) (dir, open string)
	}{
		{"the folder every account may write", func(t *testing.T, base string) (string, string) {
			return base, base
		}},
		{"the folder every account may write, sticky", func(t *testing.T, base string) (string, string) {
			return base, base
		}},
		{"a parent every account may write", func(t *testing.T, base string) (string, string) {
			return made(t, filepath.Join(base, "data")), base
		}},
		{"a parent its group, with another account in it, may write", func(t *testing.T, base string) (string, string) {
			return made(t, filepath.Join(base, "data")), base
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

			inData(t, dir)

			d := Default()
			if err := d.EnsureAll(); err != nil {
				t.Fatalf("EnsureAll(%s) = %v", c.name, err)
			}

			if got := mode(t, d.Root); got != 0o700 {
				t.Errorf("the root under %s is %v, want 0700", c.name, got)
			}

			if err := d.Check(); err != nil {
				t.Errorf("Check(a root under %s) = %v", c.name, err)
			}

			if got := lmode(t, open); got != before {
				t.Errorf("%s became %v, was %v: a folder above a root is never changed", open, got, before)
			}
		})
	}
}

// TestAMissingDataFolderIsRefused: the folder the root is in is the system's, and one that is not there
// is refused, naming it, with nothing made: no folder on the way to it, nor the root.
func TestAMissingDataFolderIsRefused(t *testing.T) {
	base := t.TempDir()
	missing := filepath.Join(base, "var", "lib")
	inData(t, missing)

	if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), filepath.Join(base, "var")) {
		t.Errorf("EnsureAll in a data folder not there = %v, want a refusal naming what is missing", err)
	}

	if entries, err := os.ReadDir(base); err != nil || len(entries) > 0 {
		t.Errorf("EnsureAll in a data folder not there made %v (%v)", entries, err)
	}
}

// made makes the directory dir, at 0700, with every folder on the way to it, and is dir.
func made(t *testing.T, dir string) string {
	t.Helper()

	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	return dir
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
