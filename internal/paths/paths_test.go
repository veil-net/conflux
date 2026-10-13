package paths

import (
	"path/filepath"
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
