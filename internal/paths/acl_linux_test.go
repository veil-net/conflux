package paths

import (
	"os"
	"os/user"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

// TestEnsureAllReadsAPOSIXACL: an ACL can let accounts write a directory that its mode does
// not show, and once there is one the mode's group bits are its mask rather than what the
// group may do. So a CONFLUX_DIR under a parent whose ACL lets another account or group
// write is refused, though its mode, 0770 with a group of this account's alone, would pass;
// one whose mask takes that write away, or whose ACL names only this account, is not.
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
	}{
		{"another account may write", posixACL(
			[3]uint32{0x01, 7, none}, [3]uint32{0x02, 7, 65534}, [3]uint32{0x04, 5, none},
			[3]uint32{0x10, 7, none}, [3]uint32{0x20, 0, none}), "uid 65534"},
		{"another group may write", posixACL(
			[3]uint32{0x01, 7, none}, [3]uint32{0x04, 5, none}, [3]uint32{0x08, 7, 0},
			[3]uint32{0x10, 7, none}, [3]uint32{0x20, 0, none}), "gid 0"},
		{"the mask takes the write away", posixACL(
			[3]uint32{0x01, 7, none}, [3]uint32{0x02, 7, 65534}, [3]uint32{0x04, 5, none},
			[3]uint32{0x10, 5, none}, [3]uint32{0x20, 0, none}), ""},
		{"only this account may write", posixACL(
			[3]uint32{0x01, 7, none}, [3]uint32{0x02, 7, uint32(os.Geteuid())}, [3]uint32{0x04, 7, none},
			[3]uint32{0x10, 7, none}, [3]uint32{0x20, 0, none}), ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			// The parent's own group lets in this account alone; any other lets in another.
			parent := groupWritableParent(t, func(own bool) ([]string, error) {
				if own {
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
