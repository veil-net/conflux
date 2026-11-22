package paths

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestARootsPOSIXACLIsJudged: an ACL can let accounts write a directory that its mode does not show.
// A root of this account's own whose POSIX ACL lets uid 65534 write it, through a mask of rwx, is not as
// conflux makes a root: the readers' check refuses it, naming that uid, and EnsureAll removes it, what it
// held with it, and makes it afresh. One a parent's default ACL passes on to the root conflux makes there takes its mask
// from the 0700 the root is made at, which lets nobody write it, and that root is taken.
func TestARootsPOSIXACLIsJudged(t *testing.T) {
	t.Run("on the root", func(t *testing.T) {
		inData(t, t.TempDir())

		d := Default()
		if err := d.EnsureAll(); err != nil {
			t.Fatal(err)
		}

		planted := filepath.Join(d.Root, "planted")
		if err := os.WriteFile(planted, []byte("uid 65534's"), 0o600); err != nil {
			t.Fatal(err)
		}

		if err := unix.Setxattr(d.Root, "system.posix_acl_access", anotherMayWrite, 0); err != nil {
			t.Fatalf("give %s an ACL: %v", d.Root, err)
		}

		if err := d.Check(); err == nil || !strings.Contains(err.Error(), "uid 65534") {
			t.Errorf("Check(a root whose POSIX ACL lets uid 65534 write it) = %v, want a refusal naming that uid", err)
		}

		if err := d.EnsureAll(); err != nil {
			t.Fatal(err)
		}

		if err := d.Check(); err != nil {
			t.Errorf("Check(the root EnsureAll made afresh) = %v", err)
		}

		if _, err := os.Lstat(planted); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("the root EnsureAll made afresh holds what was in it (Lstat: %v)", err)
		}
	})

	t.Run("passed on by its parent", func(t *testing.T) {
		parent := t.TempDir()
		if err := unix.Setxattr(parent, "system.posix_acl_default", anotherMayWrite, 0); err != nil {
			t.Fatalf("give %s a default ACL: %v", parent, err)
		}

		inData(t, parent)
		if err := Default().EnsureAll(); err != nil {
			t.Errorf("EnsureAll(a root made under a default ACL that lets another account write) = %v", err)
		}

		if err := Default().Check(); err != nil {
			t.Errorf("Check(a root made under a default ACL that lets another account write) = %v", err)
		}
	})
}
