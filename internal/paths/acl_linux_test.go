package paths

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
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

	const none = 1<<32 - 1 // the id of an entry that names nobody

	for _, c := range []struct {
		name    string
		acl     []byte
		refused string
		shared  bool // the parent's own group lets in another account too
	}{
		{"another account may write", posixACL(
			[3]uint32{0x01, 7, none}, [3]uint32{0x02, 7, 65534}, [3]uint32{0x04, 5, none},
			[3]uint32{0x10, 7, none}, [3]uint32{0x20, 0, none}), "uid 65534", false},
		{"another group may write", posixACL(
			[3]uint32{0x01, 7, none}, [3]uint32{0x04, 5, none}, [3]uint32{0x08, 7, 0},
			[3]uint32{0x10, 7, none}, [3]uint32{0x20, 0, none}), "gid 0", false},
		{"the mask takes the write away", posixACL(
			[3]uint32{0x01, 7, none}, [3]uint32{0x02, 7, 65534}, [3]uint32{0x04, 5, none},
			[3]uint32{0x10, 5, none}, [3]uint32{0x20, 0, none}), "", false},
		{"only this account may write", posixACL(
			[3]uint32{0x01, 7, none}, [3]uint32{0x02, 7, uint32(os.Geteuid())}, [3]uint32{0x04, 7, none},
			[3]uint32{0x10, 7, none}, [3]uint32{0x20, 0, none}), "", false},
		{"its group may not write, though the mask would let it", posixACL(
			[3]uint32{0x01, 7, none}, [3]uint32{0x02, 7, uint32(os.Geteuid())}, [3]uint32{0x04, 5, none},
			[3]uint32{0x10, 7, none}, [3]uint32{0x20, 0, none}), "", true},
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

// TestEnsureAllLeavesTheRootsPOSIXACLToTheNarrowing: a POSIX ACL's mask is the mode's group bits,
// so narrowing a root to 0700 takes the write from every entry in it. One found letting another
// account write the root is narrowed and accepted, and lets nobody write it afterwards; one a
// parent's default ACL passes on to the root conflux makes there takes its mask from the 0700
// the root is made at, and that root is accepted too.
func TestEnsureAllLeavesTheRootsPOSIXACLToTheNarrowing(t *testing.T) {
	const none = 1<<32 - 1

	another := posixACL([3]uint32{0x01, 7, none}, [3]uint32{0x02, 7, 65534}, [3]uint32{0x04, 5, none},
		[3]uint32{0x10, 7, none}, [3]uint32{0x20, 0, none})

	t.Run("on the root", func(t *testing.T) {
		root := filepath.Join(t.TempDir(), "conflux")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}

		if err := unix.Setxattr(root, "system.posix_acl_access", another, 0); err != nil {
			t.Fatalf("give %s an ACL: %v", root, err)
		}

		t.Setenv("CONFLUX_DIR", root)
		ensureAllRefuses(t, "a root whose own POSIX ACL lets another account write", "")

		b := make([]byte, 256)

		n, err := unix.Getxattr(root, "system.posix_acl_access", b)
		if err != nil {
			t.Fatal(err)
		}

		entries, err := linuxACL(b[:n])
		if err != nil {
			t.Fatal(err)
		}

		if got := mode(t, root); got != 0o700 || len(posixWriters(entries)) != 0 {
			t.Errorf("the root is %#o after EnsureAll, its ACL letting %+v write; want 0700, nobody",
				got, posixWriters(entries))
		}
	})

	t.Run("passed on by its parent", func(t *testing.T) {
		parent := t.TempDir()
		if err := unix.Setxattr(parent, "system.posix_acl_default", another, 0); err != nil {
			t.Fatalf("give %s a default ACL: %v", parent, err)
		}

		t.Setenv("CONFLUX_DIR", filepath.Join(parent, "conflux"))
		ensureAllRefuses(t, "a root made under a default ACL that lets another account write", "")
	})
}
