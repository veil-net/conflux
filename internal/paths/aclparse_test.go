package paths

import (
	"bytes"
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

// posixNone is the id of a POSIX.1e entry that names nobody: the owner's, the group's, the mask's
// or everybody else's.
const posixNone = 1<<32 - 1

// anotherMayWrite is a POSIX.1e access ACL that lets uid 65534 write, through a mask of rwx, its
// group read and search, and everybody else nothing (TestPOSIXWriters holds it to that).
var anotherMayWrite = posixACL([3]uint32{0x01, 7, posixNone}, [3]uint32{0x02, 7, 65534},
	[3]uint32{0x04, 5, posixNone}, [3]uint32{0x10, 7, posixNone}, [3]uint32{0x20, 0, posixNone})

// TestPOSIXWriters: who a POSIX.1e access ACL lets write, read from the bytes Linux keeps it
// in -- each named user and group and the directory's own group, as the mask leaves their write,
// and never the owner or everybody else, which the mode's bits are -- and an attribute in any
// other shape refused rather than read as allowing nobody.
func TestPOSIXWriters(t *testing.T) {
	another, err := linuxACL(anotherMayWrite)
	if err != nil || !slices.Equal(posixWriters(another), []writer{{who: aUser, id: 65534}}) {
		t.Errorf("anotherMayWrite lets %+v write (%v), want uid 65534 alone", posixWriters(another), err)
	}

	entries, err := linuxACL(posixACL(
		[3]uint32{0x01, 7, posixNone}, [3]uint32{0x02, 6, 1001}, [3]uint32{0x02, 5, 1002}, [3]uint32{0x04, 7, posixNone},
		[3]uint32{0x08, 2, 50}, [3]uint32{0x10, 7, posixNone}, [3]uint32{0x20, 7, posixNone}))
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
		append(posixACL([3]uint32{0x01, 7, posixNone}), 0, 0, 0), // an entry cut short
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
// everyone@ write alone, and deny entries and rights that write nothing are not read. group@'s and
// everyone@'s right only to add, passed on by nothing, is the mode's write bit.
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
		[5]uint32{0x02, 1003, nfs4WriteACL, allow},                         // changing its ACL, too
		[5]uint32{0x02, 1004, nfs4DeleteChild, allow},                      // deleting what is in it, too
		[5]uint32{0x08, 61, nfs4AddFile, allow},                            // each right to add, alone
		[5]uint32{0x04, 0, nfs4AddSubdirectory, allow},
	)

	want := []writer{
		{who: everyone}, {who: aUser, id: 1002, pastSticky: true}, {who: aGroup, id: 60, pastSticky: true},
		{who: aUser, id: 1003, pastSticky: true}, {who: aUser, id: 1004, pastSticky: true}, {who: aGroup, id: 61},
		{who: theGroup},
	}
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
		{"a permit to add a directory", kauthAttrBuf(kauthEntry{someone, kauthPermit, kauthAppendData}),
			[]writer{{who: anAccount, uuid: "5B1E0F1C-2D3E-4F50-6172-8394A5B6C7D8"}}},
		{"everybody may change its ACL", kauthAttrBuf(kauthEntry{kauthEveryone, kauthPermit, kauthWriteSecurity}),
			[]writer{{who: everyone, pastSticky: true}}},
		{"everybody may take it", kauthAttrBuf(kauthEntry{kauthEveryone, kauthPermit, kauthTakeOwnership}),
			[]writer{{who: everyone, pastSticky: true}}},
		{"everybody may do anything to it", kauthAttrBuf(kauthEntry{kauthEveryone, kauthPermit, kauthGenericAll}),
			[]writer{{who: everyone, pastSticky: true}}},
		{"everybody may write it, generically", kauthAttrBuf(kauthEntry{kauthEveryone, kauthPermit, kauthGenericWrite}),
			[]writer{{who: everyone, pastSticky: true}}},
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

// windowsACL is a Windows ACL holding aces, as GetSecurityInfo hands a DACL back: its revision, its
// size and its entries' count, then the entries.
func windowsACL(aces ...[]byte) []byte {
	var body []byte
	for _, a := range aces {
		body = append(body, a...)
	}

	b := []byte{4, 0}
	b = binary.LittleEndian.AppendUint16(b, uint16(8+len(body)))
	b = binary.LittleEndian.AppendUint16(b, uint16(len(aces)))
	b = binary.LittleEndian.AppendUint16(b, 0)

	return append(b, body...)
}

// windowsACE is an ACE of kind and flags holding body: its rights, and what its kind holds after.
func windowsACE(kind, flags byte, body ...[]byte) []byte {
	var b []byte
	for _, part := range body {
		b = append(b, part...)
	}

	return append(binary.LittleEndian.AppendUint16([]byte{kind, flags}, uint16(4+len(b))), b...)
}

// windowsSIDOf is the SID S-1-authority-subs... as an ACL holds it.
func windowsSIDOf(authority byte, subs ...uint32) []byte {
	b := []byte{1, byte(len(subs)), 0, 0, 0, 0, 0, authority}
	for _, s := range subs {
		b = binary.LittleEndian.AppendUint32(b, s)
	}

	return b
}

func le32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

func le16(v uint16) []byte { return binary.LittleEndian.AppendUint16(nil, v) }

// TestWindowsGrants: what a Windows DACL allows on the object itself and passes on to what is made in
// it, read from its bytes. An allowed entry counts, one that only passes its rights on among them, and
// so does its callback form, whose condition AccessCheck may find true, either object form with no
// object type to narrow it, whether or not it names a kind of child to pass itself on to, and a
// compound one, by its client's SID; one with an object type allows nothing on a file, nor does a deny,
// an audit or a label. An ACL in any other shape, or holding an entry of a type no Windows writes, is
// refused rather than read as allowing nobody.
func TestWindowsGrants(t *testing.T) {
	users, mallory, guest := windowsSIDOf(5, 32, 545), windowsSIDOf(5, 21, 1, 2, 3, 1001), windowsSIDOf(5, 21, 1, 2, 3, 501)
	guid := bytes.Repeat([]byte{0xab}, 16)
	condition := []byte("artx\x01\x00\x00\x00")

	acl := windowsACL(
		windowsACE(aceAllowed, 0, le32(0x2), users),                                              // add a file
		windowsACE(0x1, 0, le32(0x2), mallory),                                                   // a deny
		windowsACE(aceAllowed, 0x8|0x2, le32(0x10000), mallory),                                  // passed on alone
		windowsACE(aceAllowedCallback, 0, le32(0x100), mallory, condition),                       // write attributes, if
		windowsACE(aceAllowedObject, 0, le32(0x40000), le32(0), guest),                           // change the DACL
		windowsACE(aceAllowedObject, 0, le32(0x80000), le32(aceObjectType), guid, mallory),       // a property's
		windowsACE(aceAllowedObject, 0x2, le32(0x40), le32(aceInheritedObjectType), guid, guest), // to children of a kind
		windowsACE(aceAllowedCallbackObject, 0, le32(0x10000), le32(0), users, condition),        // delete, if
		windowsACE(0x2, 0x40, le32(0x2), mallory),                                                // an audit
		windowsACE(0x11, 0, le32(0x1), windowsSIDOf(16, 0x2000)),                                 // a label
		windowsACE(0x4, 0, le32(0x40000), le16(1), le16(0), guest, mallory),                      // compound, its client's
	)

	want := []windowsGrant{
		{0x2, users}, {0x10000, mallory}, {0x100, mallory}, {0x40000, guest}, {0x40, guest}, {0x10000, users},
		{0x40000, mallory},
	}

	same := func(a, b windowsGrant) bool { return a.rights == b.rights && bytes.Equal(a.sid, b.sid) }

	if got, err := windowsGrants(acl); err != nil || !slices.EqualFunc(got, want, same) {
		t.Errorf("windowsGrants = %x, %v; want %x", got, err, want)
	}

	if got, err := windowsGrants(windowsACL()); err != nil || len(got) != 0 {
		t.Errorf("windowsGrants(an empty ACL) = %x, %v; want nobody", got, err)
	}

	tooLong := windowsACL(windowsACE(aceAllowed, 0, le32(0x2), users))
	binary.LittleEndian.PutUint16(tooLong[2:], uint16(len(tooLong)+1))

	overrun := windowsACL(windowsACE(aceAllowed, 0, le32(0x2), users))
	binary.LittleEndian.PutUint16(overrun[10:], 64) // the ACE's size

	missing := windowsACL(windowsACE(aceAllowed, 0, le32(0x2), users))
	binary.LittleEndian.PutUint16(missing[4:], 2) // the count of ACEs

	underrun := windowsACL(windowsACE(aceAllowed, 0, le32(0x2), users))
	binary.LittleEndian.PutUint16(underrun[10:], 2) // the ACE's size, short of its own header

	for name, b := range map[string][]byte{
		"shorter than its header":              windowsACL()[:6],
		"longer than it is":                    tooLong,
		"an ACE past its end":                  overrun,
		"an ACE shorter than its header":       underrun,
		"more ACEs than it holds":              missing,
		"an allowed ACE cut inside its rights": windowsACL(windowsACE(aceAllowed, 0, []byte{2, 0})),
		"a SID past its ACE":                   windowsACL(windowsACE(aceAllowed, 0, le32(0x2), users[:12])),
		"a SID of another revision":            windowsACL(windowsACE(aceAllowed, 0, le32(0x2), append([]byte{2}, users[1:]...))),
		"an object ACE without flags":          windowsACL(windowsACE(aceAllowedObject, 0, le32(0x2))),
		"a compound ACE without its client":    windowsACL(windowsACE(0x4, 0, le32(0x2), le16(1), le16(0), guest)),
		"an ACE of a type no Windows writes":   windowsACL(windowsACE(0x14, 0, le32(0x2), users)),
	} {
		if _, err := windowsGrants(b); !errors.Is(err, errACL) {
			t.Errorf("windowsGrants(an ACL %s) = %v, want errACL", name, err)
		}
	}
}
