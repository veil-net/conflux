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
// root is refused. Read through getattrlist, so it runs on macOS alone: in CI's platforms job.
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
}
