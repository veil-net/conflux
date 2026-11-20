package cli

import (
	"encoding/binary"
	"errors"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/veil-net/conflux/internal/privcheck"
)

// TestAReaderRefusesARootAnACLLetsAnotherAccountWrite: a root's mode is not the whole of who may
// write it, so every reader reads its POSIX ACL too: one that lets uid 65534 write it, its mask
// letting the entry through, is refused, naming that account, with nothing in it read, made,
// stopped or removed (readersRefuse). Skipped where the file system keeps no ACLs.
func TestAReaderRefusesARootAnACLLetsAnotherAccountWrite(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	d := plantedRoot(t)

	// POSIX.1e's access ACL as Linux keeps it: a version, then each entry's tag, its rights and
	// the id it names -- the owner, uid 65534, the owning group, the mask and everybody else.
	acl := binary.LittleEndian.AppendUint32(nil, 2)
	for _, e := range [][3]uint32{{0x01, 7, ^uint32(0)}, {0x02, 7, 65534}, {0x04, 0, ^uint32(0)},
		{0x10, 7, ^uint32(0)}, {0x20, 0, ^uint32(0)}} {
		acl = binary.LittleEndian.AppendUint16(acl, uint16(e[0]))
		acl = binary.LittleEndian.AppendUint16(acl, uint16(e[1]))
		acl = binary.LittleEndian.AppendUint32(acl, e[2])
	}

	if err := unix.Setxattr(d.State, "system.posix_acl_access", acl, 0); errors.Is(err, unix.EOPNOTSUPP) {
		t.Skipf("the file system %s is on keeps no ACLs", d.State)
	} else if err != nil {
		t.Fatal(err)
	}

	readersRefuse(t, d, "uid 65534")
}
