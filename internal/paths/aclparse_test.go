package paths

import (
	"encoding/binary"
	"errors"
	"slices"
	"testing"
)

// posixACL is an access ACL as Linux keeps it in system.posix_acl_access, which setfacl
// writes: a version, then each entry's tag, permissions and id, little-endian.
func posixACL(entries ...[3]uint32) []byte {
	b := binary.LittleEndian.AppendUint32(nil, 2)
	for _, e := range entries {
		b = binary.LittleEndian.AppendUint16(b, uint16(e[0]))
		b = binary.LittleEndian.AppendUint16(b, uint16(e[1]))
		b = binary.LittleEndian.AppendUint32(b, e[2])
	}

	return b
}

// TestPOSIXWriters: who a POSIX.1e access ACL lets write, read from the bytes Linux keeps it
// in -- each named user and group and the directory's own group, as the mask leaves their write,
// and never the owner or everybody else, which the mode's bits are -- and an attribute in any
// other shape refused rather than read as allowing nobody.
func TestPOSIXWriters(t *testing.T) {
	const none = 1<<32 - 1

	entries, err := linuxACL(posixACL(
		[3]uint32{0x01, 7, none}, [3]uint32{0x02, 6, 1001}, [3]uint32{0x02, 5, 1002}, [3]uint32{0x04, 7, none},
		[3]uint32{0x08, 2, 50}, [3]uint32{0x10, 7, none}, [3]uint32{0x20, 7, none}))
	if err != nil {
		t.Fatal(err)
	}

	want := []writer{{who: aUser, id: 1001}, {who: theGroup}, {who: aGroup, id: 50}}
	if got := posixWriters(entries); !slices.Equal(got, want) {
		t.Errorf("posixWriters = %+v, want %+v", got, want)
	}

	// A mask without write leaves nobody but the owner and everybody else.
	masked := append(slices.Clone(entries[:6]), posixEntry{tag: posixMask, perm: 5})
	if got := posixWriters(masked); len(got) != 0 {
		t.Errorf("posixWriters under a mask of r-x = %+v, want nobody", got)
	}

	for _, b := range [][]byte{
		nil,
		binary.LittleEndian.AppendUint32(nil, 1), // another version
		append(posixACL([3]uint32{0x01, 7, none}), 0, 0, 0), // an entry cut short
	} {
		if _, err := linuxACL(b); !errors.Is(err, errACL) {
			t.Errorf("linuxACL(%x) = %v, want errACL", b, err)
		}
	}
}
