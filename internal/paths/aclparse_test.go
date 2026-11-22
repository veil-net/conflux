package paths

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"
	"testing"
)

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
