package paths

import (
	"errors"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestEnsureAllReadsAPOSIXACL: an ACL can let accounts write a directory that its mode does
// not show, and once there is one the mode's group bits are its mask rather than what the
// group may do. So a CONFLUX_DIR under a parent whose ACL lets another account or group
// write is refused, though its mode, 0770 with a group of this account's alone, would pass;
// one whose mask takes that write away, or whose ACL names only this account, is not, and nor is
// one whose group, with another account in it, may not write though the mask would let it.
func TestEnsureAllReadsAPOSIXACL(t *testing.T) {
	me, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name    string
		acl     []byte
		refused string
		shared  bool // the parent's own group lets in another account too
	}{
		{"another account may write", anotherMayWrite, "uid 65534", false},
		{"another group may write", posixACL(
			[3]uint32{0x01, 7, posixNone}, [3]uint32{0x04, 5, posixNone}, [3]uint32{0x08, 7, 0},
			[3]uint32{0x10, 7, posixNone}, [3]uint32{0x20, 0, posixNone}), "gid 0", false},
		{"the mask takes the write away", posixACL(
			[3]uint32{0x01, 7, posixNone}, [3]uint32{0x02, 7, 65534}, [3]uint32{0x04, 5, posixNone},
			[3]uint32{0x10, 5, posixNone}, [3]uint32{0x20, 0, posixNone}), "", false},
		{"only this account may write", posixACL(
			[3]uint32{0x01, 7, posixNone}, [3]uint32{0x02, 7, uint32(os.Geteuid())}, [3]uint32{0x04, 7, posixNone},
			[3]uint32{0x10, 7, posixNone}, [3]uint32{0x20, 0, posixNone}), "", false},
		{"its group may not write, though the mask would let it", posixACL(
			[3]uint32{0x01, 7, posixNone}, [3]uint32{0x02, 7, uint32(os.Geteuid())}, [3]uint32{0x04, 5, posixNone},
			[3]uint32{0x10, 7, posixNone}, [3]uint32{0x20, 0, posixNone}), "", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			// The parent's own group lets in this account alone, unless shared; any other lets
			// in another.
			parent := groupWritableParent(t, func(own bool) ([]string, error) {
				if own && !c.shared {
					return []string{me.Username}, nil
				}

				return []string{"mallory"}, nil
			})

			if err := unix.Setxattr(parent, "system.posix_acl_access", c.acl, 0); err != nil {
				t.Fatalf("give %s an ACL: %v", parent, err)
			}

			ensureAllRefuses(t, "a root under a parent where "+c.name, c.refused)
		})
	}
}

// TestARootsPOSIXACLIsJudged: an ACL can let accounts write a directory that its mode does not show.
// A root of this account's own whose POSIX ACL lets uid 65534 write it, through a mask of rwx, is not as
// conflux makes a root: the readers' check refuses it, naming that uid, and EnsureAll removes it, what it
// held with it, and makes it afresh. One a parent's default ACL passes on to the root conflux makes there takes its mask
// from the 0700 the root is made at, which lets nobody write it, and that root is taken.
func TestARootsPOSIXACLIsJudged(t *testing.T) {
	t.Run("on the root", func(t *testing.T) {
		t.Setenv("CONFLUX_DIR", t.TempDir())

		d := Default()
		if err := d.EnsureAll(); err != nil {
			t.Fatal(err)
		}

		planted := filepath.Join(d.State, "planted")
		if err := os.WriteFile(planted, []byte("uid 65534's"), 0o600); err != nil {
			t.Fatal(err)
		}

		if err := unix.Setxattr(d.State, "system.posix_acl_access", anotherMayWrite, 0); err != nil {
			t.Fatalf("give %s an ACL: %v", d.State, err)
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

		t.Setenv("CONFLUX_DIR", filepath.Join(parent, "conflux"))
		ensureAllRefuses(t, "a root made under a default ACL that lets another account write", "")

		if err := Default().Check(); err != nil {
			t.Errorf("Check(a root made under a default ACL that lets another account write) = %v", err)
		}
	})
}
