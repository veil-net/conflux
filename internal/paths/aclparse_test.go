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

// freebsdBuf is FreeBSD's struct acl holding entries, each a tag, an id, permissions, an NFSv4
// entry type and flags, as __acl_get_link fills it.
func freebsdBuf(entries ...[5]uint32) []byte {
	b := make([]byte, freebsdACLSize)
	binary.NativeEndian.PutUint32(b, freebsdMaxEntries)
	binary.NativeEndian.PutUint32(b[4:], uint32(len(entries)))

	for i, e := range entries {
		at := b[24+16*i:]
		binary.NativeEndian.PutUint32(at, e[0])
		binary.NativeEndian.PutUint32(at[4:], e[1])
		binary.NativeEndian.PutUint32(at[8:], e[2])
		binary.NativeEndian.PutUint16(at[12:], uint16(e[3]))
		binary.NativeEndian.PutUint16(at[14:], uint16(e[4]))
	}

	return b
}

// TestFreeBSDACL: who FreeBSD's ACLs let write. A POSIX.1e access ACL is read as Linux's is,
// its trivial three entries letting nobody past the mode's bits. Of an NFSv4 ACL, each allow
// entry that adds to the directory or, past the sticky bit, deletes from it, deletes it, or
// changes its ACL or owner, other than owner@'s; ZFS's trivial ACL for a 1777 /tmp lets
// everyone@ write alone, and deny entries and rights that write nothing are not read.
func TestFreeBSDACL(t *testing.T) {
	const allow, deny = nfs4Allow, 0x0200

	trivial := freebsdBuf([5]uint32{0x01, 0, 7}, [5]uint32{0x04, 0, 5}, [5]uint32{0x20, 0, 5})
	if got, err := freebsdACL(trivial, false); err != nil || len(got) != 0 {
		t.Errorf("a trivial POSIX.1e ACL, r-x for its group = %+v, %v; want nobody", got, err)
	}

	named := freebsdBuf([5]uint32{0x01, 0, 7}, [5]uint32{0x02, 1001, 7}, [5]uint32{0x04, 0, 5},
		[5]uint32{0x10, 0, 7}, [5]uint32{0x20, 0, 5})
	if got, err := freebsdACL(named, false); err != nil || !slices.Equal(got, []writer{{who: aUser, id: 1001}}) {
		t.Errorf("a POSIX.1e ACL naming uid 1001 rwx = %+v, %v; want uid 1001", got, err)
	}

	tmp := freebsdBuf(
		[5]uint32{0x01, 0, 0x1ffff, allow},                                 // owner@: everything
		[5]uint32{0x04, 0, 0x8 | 0x1, allow},                               // group@: list, search
		[5]uint32{0x40, 0, nfs4AddFile | nfs4AddSubdirectory | 0x8, allow}, // everyone@: write, as 1777 gives
		[5]uint32{0x02, 1001, nfs4WriteACL, deny},                          // a deny takes nothing away
		[5]uint32{0x08, 50, 0x8 | 0x200, allow},                            // reading writes nothing
		[5]uint32{0x02, 1002, nfs4WriteOwner, allow},                       // past the sticky bit
		[5]uint32{0x08, 60, nfs4Delete, allow},                             // deleting the directory itself, too
	)

	want := []writer{{who: everyone}, {who: aUser, id: 1002, pastSticky: true}, {who: aGroup, id: 60, pastSticky: true}}
	if got, err := freebsdACL(tmp, true); err != nil || !slices.Equal(got, want) {
		t.Errorf("freebsdACL(an NFSv4 ACL) = %+v, %v; want %+v", got, err, want)
	}

	for _, b := range [][]byte{trivial[:100], freebsdBuf(make([][5]uint32, 0)...)[:24]} {
		if _, err := freebsdACL(b, true); !errors.Is(err, errACL) {
			t.Errorf("freebsdACL of %d bytes = %v, want errACL", len(b), err)
		}
	}

	if _, err := freebsdACL(freebsdBuf([5]uint32{0x80, 0, nfs4AddFile, allow}), true); !errors.Is(err, errACL) {
		t.Errorf("an NFSv4 entry of a tag no kernel writes = %v, want errACL", err)
	}
}

// kauthAttrBuf is what getattrlist returns for ATTR_CMN_EXTENDED_SECURITY: the length, an
// attrreference to the kauth_filesec just after it, and the kauth_filesec, holding entries
// of a UUID, flags and rights -- or, given none, no ACL at all.
func kauthAttrBuf(entries ...kauthEntry) []byte {
	b := make([]byte, 12)

	if entries != nil {
		fsec := binary.NativeEndian.AppendUint32(nil, kauthMagic)
		fsec = append(fsec, make([]byte, 32)...) // owner and group UUIDs, which getattrlist zeroes
		fsec = binary.NativeEndian.AppendUint32(fsec, uint32(len(entries)))
		fsec = binary.NativeEndian.AppendUint32(fsec, 0)

		for _, e := range entries {
			fsec = append(fsec, e.uuid[:]...)
			fsec = binary.NativeEndian.AppendUint32(fsec, e.flags)
			fsec = binary.NativeEndian.AppendUint32(fsec, e.rights)
		}

		binary.NativeEndian.PutUint32(b[4:], 8) // from the attrreference, at 4, to 12
		binary.NativeEndian.PutUint32(b[8:], uint32(len(fsec)))
		b = append(b, fsec...)
	}

	binary.NativeEndian.PutUint32(b, uint32(len(b)))

	return b
}

type kauthEntry struct {
	uuid          [16]byte
	flags, rights uint32
}

// TestKauthWriters: who macOS's extended ACL lets write -- each permit entry granting a right to
// write the directory, everybody by the everyone UUID and anybody else by theirs -- while the
// everyone-deny-delete on a home directory, a permit to read, and no ACL at all let nobody.
func TestKauthWriters(t *testing.T) {
	const deny, inherits = 2, 1<<5 | 1<<6

	someone := [16]byte{0x5b, 0x1e, 0x0f, 0x1c, 0x2d, 0x3e, 0x4f, 0x50, 0x61, 0x72, 0x83, 0x94, 0xa5, 0xb6, 0xc7, 0xd8}

	for _, c := range []struct {
		name string
		b    []byte
		want []writer
	}{
		{"no ACL", kauthAttrBuf(), nil},
		{"a home directory's", kauthAttrBuf(kauthEntry{kauthEveryone, deny, kauthDelete}), nil},
		{"a permit to read", kauthAttrBuf(kauthEntry{someone, kauthPermit, 1<<1 | 1<<3}), nil},
		{"a permit to add a file", kauthAttrBuf(kauthEntry{someone, kauthPermit | inherits, kauthWriteData}),
			[]writer{{who: anAccount, uuid: "5B1E0F1C-2D3E-4F50-6172-8394A5B6C7D8"}}},
		{"everybody may delete what is in it", kauthAttrBuf(kauthEntry{kauthEveryone, kauthPermit, kauthDeleteChild}),
			[]writer{{who: everyone, pastSticky: true}}},
		{"everybody may delete it", kauthAttrBuf(kauthEntry{kauthEveryone, kauthPermit, kauthDelete}),
			[]writer{{who: everyone, pastSticky: true}}},
	} {
		if got, err := kauthAttr(c.b); err != nil || !slices.Equal(got, c.want) {
			t.Errorf("%s: kauthAttr = %+v, %v; want %+v", c.name, got, err, c.want)
		}
	}

	if got, err := kauthWriters(append(binary.NativeEndian.AppendUint32(nil, kauthMagic), make([]byte, 32)...)); err == nil {
		t.Errorf("a kauth_filesec cut off before its ACL = %+v, want errACL", got)
	}

	noACL := kauthAttrBuf(kauthEntry{})
	binary.NativeEndian.PutUint32(noACL[12+36:], kauthNoACL)

	if got, err := kauthAttr(noACL); err != nil || got != nil {
		t.Errorf("a kauth_filesec saying it has no ACL = %+v, %v; want nobody", got, err)
	}

	bad := kauthAttrBuf(kauthEntry{someone, kauthPermit, kauthWriteData})
	bad[12] ^= 0xff // the magic number

	if _, err := kauthAttr(bad); !errors.Is(err, errACL) {
		t.Errorf("a kauth_filesec with another magic number = %v, want errACL", err)
	}
}
