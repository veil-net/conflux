package paths

import (
	"encoding/binary"
	"errors"
)

// Windows's DACLs, read from their bytes into what they allow on the object itself and on what is
// made in it (windowsGrants), which mover holds to who may change it: untagged, and over bytes alone,
// so the format is tested on every machine that builds conflux. An entry counts whatever it says of
// inheritance: one a root only passes on is inherited by what conflux makes inside it, so it counts as
// one that applies.

// errACL is an ACL in a shape no kernel writes.
var errACL = errors.New("an ACL conflux cannot read")

// Windows's ACL, as GetSecurityInfo hands a DACL back: a revision, a pad byte, the ACL's size and
// its entries' count, 16 bits each, and a pad; then each ACE -- its type, its flags and its size,
// and what its type holds -- little-endian whatever the machine.
const (
	aceAllowed               = 0x0  // ACCESS_ALLOWED_ACE_TYPE: rights, then a SID
	aceAllowedCompound       = 0x4  // ACCESS_ALLOWED_COMPOUND_ACE_TYPE: rights, a kind, a pad, a server's SID, a client's
	aceAllowedObject         = 0x5  // ACCESS_ALLOWED_OBJECT_ACE_TYPE: rights, flags, the GUIDs they name, a SID
	aceAllowedCallback       = 0x9  // ACCESS_ALLOWED_CALLBACK_ACE_TYPE: an allowed ACE, then a condition
	aceAllowedCallbackObject = 0xb  // ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE: an object one, then a condition
	aceLastKnown             = 0x13 // SYSTEM_SCOPED_POLICY_ID_ACE_TYPE: the last type MS-DTYP numbers

	aceObjectType          = 0x1 // ACE_OBJECT_TYPE_PRESENT
	aceInheritedObjectType = 0x2 // ACE_INHERITED_OBJECT_TYPE_PRESENT
)

// windowsGrant is an entry of a Windows ACL that allows rights on the object it is on, or on what is
// made in it: the rights, and the SID they are allowed to, as the ACL holds it.
type windowsGrant struct {
	rights uint32
	sid    []byte
}

// windowsGrants is each entry of the Windows ACL acl that allows rights on the object itself or on
// what is made in it. An allowed entry counts, and its callback form, whose
// condition AccessCheck may find true and conflux does not weigh; so do the object forms where no
// object type narrows them to a property or a kind of child -- AccessCheck, asked of a file with no
// list of object types, takes one with none for an allowed entry and one with a type as allowing
// nothing -- and a compound entry, which allows its rights to its client's SID while a server
// holding the other acts for it, counted as the client's. An entry that only passes its rights on
// counts too; a deny, an audit, an alarm or a label never does: a deny takes nothing
// away from an allow conflux counts. An entry of a type MS-DTYP does not number is refused, as an
// ACL in any other shape is, rather than read as allowing nobody: it may allow what conflux cannot
// see.
func windowsGrants(acl []byte) ([]windowsGrant, error) {
	if len(acl) < 8 {
		return nil, errACL
	}

	size, n := int(binary.LittleEndian.Uint16(acl[2:])), int(binary.LittleEndian.Uint16(acl[4:]))
	if size < 8 || size > len(acl) {
		return nil, errACL
	}

	var grants []windowsGrant

	for b := acl[8:size]; n > 0; n-- {
		if len(b) < 4 {
			return nil, errACL
		}

		kind, aceSize := b[0], int(binary.LittleEndian.Uint16(b[2:]))
		if aceSize < 4 || aceSize > len(b) {
			return nil, errACL
		}

		ace := b[4:aceSize]
		b = b[aceSize:]

		sidAt := 4

		switch kind {
		case aceAllowed, aceAllowedCallback:
		case aceAllowedCompound:
			if len(ace) < 8 {
				return nil, errACL
			}

			server, err := windowsSID(ace[8:])
			if err != nil {
				return nil, err
			}

			sidAt = 8 + len(server)
		case aceAllowedObject, aceAllowedCallbackObject:
			if len(ace) < 8 {
				return nil, errACL
			}

			present := binary.LittleEndian.Uint32(ace[4:])
			if present&aceObjectType != 0 {
				continue
			}

			if sidAt = 8; present&aceInheritedObjectType != 0 {
				sidAt += 16
			}
		default:
			if kind > aceLastKnown {
				return nil, errACL
			}

			continue
		}

		if len(ace) < sidAt {
			return nil, errACL
		}

		sid, err := windowsSID(ace[sidAt:])
		if err != nil {
			return nil, err
		}

		grants = append(grants, windowsGrant{rights: binary.LittleEndian.Uint32(ace), sid: sid})
	}

	return grants, nil
}

// windowsSID is the SID b starts with: a revision, 1, its sub-authorities' count, a 48-bit
// authority, and each sub-authority, 32 bits.
func windowsSID(b []byte) ([]byte, error) {
	if len(b) < 8 || b[0] != 1 || 8+4*int(b[1]) > len(b) {
		return nil, errACL
	}

	n := 8 + 4*int(b[1])

	return b[:n:n], nil
}
