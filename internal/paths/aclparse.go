package paths

import (
	"encoding/binary"
	"errors"
)

// The ACLs a directory above a CONFLUX_DIR may carry beside its mode, read into who they let
// write it. Untagged, and over bytes alone, so each platform's format is tested on every
// machine that builds conflux; each platform's file reads its own (extendedWriters).

// grantee is who an ACL entry lets write a directory.
type grantee int

const (
	aUser    grantee = iota // a named user, by uid
	aGroup                  // a named group, by gid
	theGroup                // the directory's own group
)

// writer is an ACL entry that lets somebody other than a directory's owner write it.
type writer struct {
	who grantee
	id  uint32 // aUser's uid or aGroup's gid
}

// POSIX.1e: tags and the write bit, as Linux's system.posix_acl_access and FreeBSD's acl(9)
// both number them.
const (
	posixUser     = 0x02
	posixGroupObj = 0x04
	posixGroup    = 0x08
	posixMask     = 0x10
	posixWrite    = 0x02
)

// posixEntry is one entry of a POSIX.1e access ACL.
type posixEntry struct{ tag, perm, id uint32 }

// posixWriters is who a POSIX.1e access ACL lets write besides the owner: each named user and
// group, and the directory's own group, each as its write survives the mask, where there is
// one. Everybody else's is the ACL's other entry, which the mode's other bits are.
func posixWriters(entries []posixEntry) []writer {
	mask := uint32(posixWrite)

	for _, e := range entries {
		if e.tag == posixMask {
			mask = e.perm
		}
	}

	var ws []writer

	for _, e := range entries {
		if e.perm&mask&posixWrite == 0 {
			continue
		}

		switch e.tag {
		case posixUser:
			ws = append(ws, writer{who: aUser, id: e.id})
		case posixGroup:
			ws = append(ws, writer{who: aGroup, id: e.id})
		case posixGroupObj:
			ws = append(ws, writer{who: theGroup})
		}
	}

	return ws
}

// errACL is an ACL in a shape no kernel writes.
var errACL = errors.New("an ACL conflux cannot read")

// linuxACL reads Linux's system.posix_acl_access: a version, 2, and then each entry's tag and
// permissions, 16 bits each, and its id, 32, little-endian whatever the machine.
func linuxACL(b []byte) ([]posixEntry, error) {
	if len(b) < 4 || binary.LittleEndian.Uint32(b) != 2 || (len(b)-4)%8 != 0 {
		return nil, errACL
	}

	var entries []posixEntry

	for b = b[4:]; len(b) > 0; b = b[8:] {
		entries = append(entries, posixEntry{
			tag:  uint32(binary.LittleEndian.Uint16(b)),
			perm: uint32(binary.LittleEndian.Uint16(b[2:])),
			id:   binary.LittleEndian.Uint32(b[4:]),
		})
	}

	return entries, nil
}
