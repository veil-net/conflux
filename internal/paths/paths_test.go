package paths

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// TestRootIsAbsoluteAndClean: the root is written into the service definition and hashed
// into its name, so every spelling of one directory has to come out the same.
func TestRootIsAbsoluteAndClean(t *testing.T) {
	cwd := t.TempDir()
	t.Chdir(cwd)

	t.Setenv("CONFLUX_DIR", filepath.Join("rel", "x")+string(filepath.Separator))

	if got, want := Root(), filepath.Join(cwd, "rel", "x"); got != want {
		t.Errorf("Root() = %q, want %q", got, want)
	}

	t.Setenv("CONFLUX_DIR", "")

	if got := Root(); got != "" {
		t.Errorf("Root() = %q with no CONFLUX_DIR, want \"\"", got)
	}
}

// TestALogDirectoryOnlyWhereThePlatformHasOne: under CONFLUX_DIR the log goes beside the
// rest only on a platform that writes the service's output to a file.
func TestALogDirectoryOnlyWhereThePlatformHasOne(t *testing.T) {
	root := t.TempDir()
	t.Setenv("CONFLUX_DIR", root)

	d := Default()

	switch platform := platformDirs().Log; {
	case platform == "" && d.Log != "":
		t.Errorf("Log = %q, but nothing on this platform writes a log file", d.Log)
	case platform != "" && d.Log != filepath.Join(root, "logs"):
		t.Errorf("Log = %q, want it under the root", d.Log)
	}
}

// foundRoot is a root as secure finds one already there: a folder named conflux, made at 0700 in a
// temporary directory of the test's, with what that passes on.
func foundRoot(t *testing.T) string {
	t.Helper()

	root := filepath.Join(t.TempDir(), "conflux")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}

	return root
}

// TestClearExceptSaysWhatItRemoved: everything in the directory but the one kept is removed, a folder
// with all it holds, and what was removed is named, for tidy to list; the one kept stays, and a
// directory not there is an error, with nothing named.
func TestClearExceptSaysWhatItRemoved(t *testing.T) {
	dir := t.TempDir()
	keep := filepath.Join(dir, "keep")

	for _, p := range []string{keep, filepath.Join(dir, "a"), filepath.Join(dir, "c", "d")} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	want := []string{filepath.Join(dir, "a"), filepath.Join(dir, "c")}

	if removed, err := ClearExcept(dir, keep); err != nil || !slices.Equal(removed, want) {
		t.Errorf("ClearExcept = %q, %v, want %q", removed, err, want)
	}

	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 1 || entries[0].Name() != "keep" {
		t.Errorf("ClearExcept left %v (%v), want only what it kept", entries, err)
	}

	if removed, err := ClearExcept(filepath.Join(dir, "not-there"), ""); err == nil || removed != nil {
		t.Errorf("ClearExcept(a directory not there) = %q, %v, want an error and nothing named", removed, err)
	}
}
