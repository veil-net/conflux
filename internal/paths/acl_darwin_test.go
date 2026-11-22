package paths

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestEnsureAllReadsTheRootsOwnACL: an entry a directory passes on lands on the root conflux makes
// inside it. The CONFLUX_DIR, and every folder above it, is the user's choice and not judged, so a
// directory whose ACL lets everybody add to what is made in it is taken, and the root made; but the
// root inherits the entry, and everybody's right to put what they like in it with it, so it is not as
// conflux makes a root, and the readers' check refuses it. So is one a CONFLUX_DIR leads to through a
// symlink, whose ACL is read where the link leads: the link's own holds nothing. Read through
// getattrlist, so it runs on macOS alone: in CI's platforms job.
func TestEnsureAllReadsTheRootsOwnACL(t *testing.T) {
	parent := t.TempDir()

	if out, err := exec.Command("/bin/chmod", "+a",
		"everyone allow add_file,add_subdirectory,file_inherit,directory_inherit", parent).CombinedOutput(); err != nil {
		t.Fatalf("chmod +a: %v\n%s", err, out)
	}

	t.Setenv("CONFLUX_DIR", filepath.Join(parent, "conflux"))

	checkRefuses(t, "a root that inherited everybody's right to add to it")

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

		checkRefuses(t, "a root reached through a symlink, which inherited everybody's right to add to it")
	})
}

// checkRefuses is EnsureAll making root, and the readers' check refusing it for what everybody may do.
func checkRefuses(t *testing.T, root string) {
	t.Helper()

	if err := Default().EnsureAll(); err != nil {
		t.Fatalf("EnsureAll(%s) = %v", root, err)
	}

	if err := Default().Check(); err == nil || !strings.Contains(err.Error(), "anybody") {
		t.Errorf("Check(%s) = %v, want a refusal naming anybody", root, err)
	}
}
