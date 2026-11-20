package paths

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestEnsureAllReadsTheRootsOwnACL: an entry a directory passes on lands on the root conflux makes
// inside it. A sticky directory whose ACL lets everybody add to it is let through, as its mode's
// bits would be, since nobody may move out of it what is not theirs; but the root made there
// inherits the entry, and everybody's right to put what they like in the root with it, so the
// root is refused. So is one a CONFLUX_DIR leads to through a symlink, whose ACL is read where
// the link leads: the link's own holds nothing. Read through getattrlist, so it runs on macOS
// alone: in CI's platforms job.
func TestEnsureAllReadsTheRootsOwnACL(t *testing.T) {
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700|os.ModeSticky); err != nil {
		t.Fatal(err)
	}

	if out, err := exec.Command("/bin/chmod", "+a",
		"everyone allow add_file,add_subdirectory,file_inherit,directory_inherit", parent).CombinedOutput(); err != nil {
		t.Fatalf("chmod +a: %v\n%s", err, out)
	}

	t.Setenv("CONFLUX_DIR", filepath.Join(parent, "conflux"))

	ensureAllRefuses(t, "a root that inherited everybody's right to add to it", "anybody")

	t.Run("through a symlink", func(t *testing.T) {
		real := filepath.Join(parent, "real")
		if err := os.Mkdir(real, 0o700); err != nil {
			t.Fatal(err)
		}

		link := filepath.Join(t.TempDir(), "conflux")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}

		t.Setenv("CONFLUX_DIR", link)

		ensureAllRefuses(t, "a root reached through a symlink, which inherited everybody's right to add to it", "anybody")
	})
}
