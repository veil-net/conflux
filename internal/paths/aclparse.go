package paths

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// The ACLs a directory above a CONFLUX_DIR may carry beside its mode, read into who they let
// write it. Untagged, and over bytes alone, so each platform's format is tested on every
// machine that builds conflux; each platform's file reads its own (extendedWriters). An entry's
// inheritance is not read: one the directory only passes on is inherited by the root conflux
// makes inside it, so it counts as one that applies.

// grantee is who an ACL entry lets write a directory.
type grantee int

const (
	aUser     grantee = iota // a named user, by uid
	aGroup                   // a named group, by gid
	theGroup                 // the directory's own group
	everyone                 // anybody at all
	anAccount                // a user or group named by a UUID, which conflux cannot map without cgo (macOS)
)

// writer is an ACL entry that lets somebody other than a directory's owner write it.
type writer struct {
	who  grantee
	id   uint32 // aUser's uid or aGroup's gid
	uuid string // anAccount's

	// pastSticky is a right the sticky bit does not hold back: to delete what is in the
	// directory, to delete the directory itself, which the kernel grants before it looks at a
	// sticky bit, or to change its ACL or owner. Writing it, all a mode's bits or a POSIX.1e ACL
	// can grant, is held back.
	pastSticky bool
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

// FreeBSD's struct acl, which __acl_get_link fills: a count the caller sets to ACL_MAX_ENTRIES,
// the entries' count, four spare ints, then the entries -- each a tag, an id and permissions of
// 32 bits, and an NFSv4 entry type and flags of 16 -- in the machine's order.
const (
	freebsdMaxEntries = 254
	freebsdACLSize    = 24 + freebsdMaxEntries*16
)

// NFSv4 ACLs, as FreeBSD numbers them: the tags POSIX.1e does not have, the allow type, and the
// rights that write a directory -- to add a file or a directory to it and, past the sticky bit, to
// delete what is in it, to delete the directory itself, or to change its ACL or owner.
const (
	nfs4Owner    = 0x01 // owner@
	nfs4Everyone = 0x40 // everyone@
	nfs4Allow    = 0x0100

	nfs4AddFile         = 0x0010
	nfs4AddSubdirectory = 0x0020
	nfs4DeleteChild     = 0x0100
	nfs4Delete          = 0x0800
	nfs4WriteACL        = 0x2000
	nfs4WriteOwner      = 0x4000
	nfs4PastSticky      = nfs4DeleteChild | nfs4Delete | nfs4WriteACL | nfs4WriteOwner
)

// freebsdACL is who FreeBSD's struct acl lets write, read as the NFSv4 ACL or the POSIX.1e
// access ACL it was asked for. Of an NFSv4 ACL, each allow entry that grants a right to write
// the directory, but the owner's; a deny entry takes nothing away from an allow entry
// conflux counts, so it is not read.
func freebsdACL(b []byte, nfs4 bool) ([]writer, error) {
	if len(b) < freebsdACLSize {
		return nil, errACL
	}

	n := binary.NativeEndian.Uint32(b[4:])
	if n > freebsdMaxEntries {
		return nil, errACL
	}

	var (
		entries []posixEntry
		ws      []writer
	)

	for e := b[24 : 24+16*n]; len(e) > 0; e = e[16:] {
		tag, id, perm := binary.NativeEndian.Uint32(e), binary.NativeEndian.Uint32(e[4:]), binary.NativeEndian.Uint32(e[8:])

		if !nfs4 {
			entries = append(entries, posixEntry{tag: tag, perm: perm, id: id})

			continue
		}

		if binary.NativeEndian.Uint16(e[12:]) != nfs4Allow ||
			perm&(nfs4AddFile|nfs4AddSubdirectory|nfs4PastSticky) == 0 || tag == nfs4Owner {
			continue
		}

		w := writer{id: id, pastSticky: perm&nfs4PastSticky != 0}

		switch tag {
		case posixUser:
			w.who = aUser
		case posixGroup:
			w.who = aGroup
		case posixGroupObj:
			w.who = theGroup
		case nfs4Everyone:
			w.who = everyone
		default:
			return nil, errACL
		}

		ws = append(ws, w)
	}

	if !nfs4 {
		return posixWriters(entries), nil
	}

	return ws, nil
}

// macOS's extended ACL, as getattrlist hands ATTR_CMN_EXTENDED_SECURITY back: a kauth_filesec
// -- a magic number, the owner's and group's UUIDs, then a kauth_acl: the entries' count, or
// none, flags, and the entries, each a UUID, flags and rights -- in the machine's order.
const (
	kauthMagic = 0x012cc16d
	kauthNoACL = 1<<32 - 1
	kauthMax   = 128

	kauthKind   = 0xf
	kauthPermit = 1

	kauthWriteData     = 1 << 2 // add_file on a directory
	kauthDelete        = 1 << 4
	kauthAppendData    = 1 << 5 // add_subdirectory
	kauthDeleteChild   = 1 << 6
	kauthWriteSecurity = 1 << 12
	kauthTakeOwnership = 1 << 13
	kauthGenericAll    = 1 << 21
	kauthGenericWrite  = 1 << 23
	kauthPastSticky    = kauthDeleteChild | kauthDelete | kauthWriteSecurity | kauthTakeOwnership | kauthGenericAll |
		kauthGenericWrite
	kauthWritesSomehow = kauthWriteData | kauthAppendData | kauthPastSticky
)

// kauthEveryone is the UUID macOS's ACLs name everybody by: the group everyone, gid 12.
var kauthEveryone = [16]byte{0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0xab, 0xcd, 0xef, 0, 0, 0, 0x0c}

// kauthAttr is who the extended ACL getattrlist returned in b lets write: b holds the length of
// what was returned, then an attrreference -- where the kauth_filesec is, counted from the
// reference itself, and its length, 0 where there is no ACL.
func kauthAttr(b []byte) ([]writer, error) {
	if len(b) < 12 {
		return nil, errACL
	}

	off, n := int64(int32(binary.NativeEndian.Uint32(b[4:]))), int64(binary.NativeEndian.Uint32(b[8:]))
	if n == 0 {
		return nil, nil
	}

	if off < 8 || 4+off+n > int64(len(b)) {
		return nil, errACL
	}

	return kauthWriters(b[4+off : 4+off+n])
}

// kauthWriters is who a kauth_filesec lets write: each permit entry that grants a right to
// write the directory, named by its UUID, which conflux cannot map to an account without cgo, so
// none is taken for the owner's. A deny entry is not read: it takes nothing away from a permit
// conflux counts, and the everyone-deny-delete on a home directory is no grant.
func kauthWriters(b []byte) ([]writer, error) {
	if len(b) < 44 || binary.NativeEndian.Uint32(b) != kauthMagic {
		return nil, errACL
	}

	n := binary.NativeEndian.Uint32(b[36:])
	if n == kauthNoACL {
		return nil, nil
	}

	if n > kauthMax || 44+24*int(n) > len(b) {
		return nil, errACL
	}

	var ws []writer

	for e := b[44 : 44+24*n]; len(e) > 0; e = e[24:] {
		flags, rights := binary.NativeEndian.Uint32(e[16:]), binary.NativeEndian.Uint32(e[20:])
		if flags&kauthKind != kauthPermit || rights&kauthWritesSomehow == 0 {
			continue
		}

		w := writer{who: everyone, pastSticky: rights&kauthPastSticky != 0}
		if [16]byte(e[:16]) != kauthEveryone {
			w.who, w.uuid = anAccount, fmt.Sprintf("%X-%X-%X-%X-%X", e[:4], e[4:6], e[6:8], e[8:10], e[10:16])
		}

		ws = append(ws, w)
	}

	return ws, nil
}
