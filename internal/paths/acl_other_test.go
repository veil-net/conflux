//go:build !windows

package paths

import (
	"os"
	"path/filepath"
	"testing"
)

func mode(t *testing.T, dir string) os.FileMode {
	t.Helper()

	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}

	return fi.Mode().Perm()
}

// realTempDir is t.TempDir as the walk names it, no link on the way to it: a TMPDIR behind a link -- on
// macOS /var/folders, under /private -- is named by where the link leads in what the walk names.
func realTempDir(t *testing.T) string {
	t.Helper()

	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	return dir
}
