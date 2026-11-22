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

// TestTheWalkGoesAsTheKernelLooksUp: the way is walked as the kernel looks dir up, a link's target read
// from the directory the link is in, ".." included, an absolute one from the top of the volume, and
// ends at the directory dir leads to.
func TestTheWalkGoesAsTheKernelLooksUp(t *testing.T) {
	base := realTempDir(t) // under /private/var on macOS

	for _, dir := range []string{"a", "b/c", "d"} {
		if err := os.MkdirAll(filepath.Join(base, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	// a/l -> ../d/m, and d/m -> <base>/b/c, absolute: the root is b/c, reached through d.
	if err := os.Symlink("../d/m", filepath.Join(base, "a", "l")); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(filepath.Join(base, "b", "c"), filepath.Join(base, "d", "m")); err != nil {
		t.Fatal(err)
	}

	// a/up -> ../d: the walk goes back up to base, and on into d, and through m to b/c.
	if err := os.Symlink("../d", filepath.Join(base, "a", "up")); err != nil {
		t.Fatal(err)
	}

	for _, dir := range []string{filepath.Join(base, "a", "l"), filepath.Join(base, "a", "up", "m")} {
		w, err := walk(dir)
		if err != nil {
			t.Fatal(err)
		}

		if w.missing != nil || w.last().path != filepath.Join(base, "b", "c") {
			t.Errorf("the walk to %s ended at %s, %v, want %s, there", dir, w.last().path, w.missing,
				filepath.Join(base, "b", "c"))
		}

		w.close()
	}
}
