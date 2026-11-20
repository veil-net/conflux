package paths

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf16"
)

// Windows's symbolic links and junctions, read from and written as their reparse data: untagged,
// and over bytes alone, so that what conflux takes for a link leading off this machine is tested on
// every machine that builds conflux, as aclparse.go's ACLs are.

// The reparse tags of a junction (a mount point) and a symbolic link, and the flag that says a
// symbolic link's target is relative to the folder the link is in.
const (
	reparseTagMountPoint = 0xA0000003
	reparseTagSymlink    = 0xA000000C
	symlinkFlagRelative  = 0x1
)

// errNotLink is windowsLinkTarget's answer for a reparse point that is neither a symbolic link nor
// a junction: one that holds something of its own rather than naming another path.
var errNotLink = errors.New("a reparse point that is neither a symbolic link nor a junction")

// errReparse is reparse data in a shape no file system returns.
var errReparse = errors.New("reparse data conflux cannot read")

// windowsLinkTarget is where the symbolic link or junction whose reparse data (REPARSE_DATA_BUFFER)
// b holds leads, as os.Readlink names it: a relative symbolic link's target as it is written, and
// an absolute one's or a junction's, an NT path, by its drive letter (C:\x) or by its volume's GUID
// (\\?\Volume{...}\x). An NT path naming anything else -- a share by \??\UNC\, which a link to a
// UNC path or a WebDAV server's holds, or a device by its NT name -- is refused, as is a relative
// target that begins as a UNC path does: it may be another machine's, which following the link
// would sign this one in to, and this one could not judge what is there either (remote). A drive
// letter or a volume GUID is looked up in the device map of the account conflux runs as, which only
// an administrator or SYSTEM changes.
func windowsLinkTarget(b []byte) (string, error) {
	if len(b) < 8 {
		return "", errReparse
	}

	tag, n := binary.LittleEndian.Uint32(b), int(binary.LittleEndian.Uint16(b[4:]))
	if 8+n > len(b) {
		return "", errReparse
	}

	data := b[8 : 8+n]

	// SymbolicLinkReparseBuffer, or MountPointReparseBuffer: the substitute name's offset and length
	// in bytes into the names, which follow the four lengths and, for a symbolic link, its flags.
	head, relative := 8, false

	switch tag {
	case reparseTagSymlink:
		if len(data) < 12 {
			return "", errReparse
		}

		head, relative = 12, binary.LittleEndian.Uint32(data[8:])&symlinkFlagRelative != 0
	case reparseTagMountPoint:
		if len(data) < 8 {
			return "", errReparse
		}
	default:
		return "", errNotLink
	}

	at, size, names := int(binary.LittleEndian.Uint16(data)), int(binary.LittleEndian.Uint16(data[2:])), data[head:]
	if at%2 != 0 || size%2 != 0 || at+size > len(names) {
		return "", errReparse
	}

	u := make([]uint16, size/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(names[at+2*i:])
	}

	target := string(utf16.Decode(u))

	switch rest, nt := strings.CutPrefix(target, `\??\`); {
	case relative && !isUNC(target):
		return target, nil
	case !relative && nt && len(rest) >= 3 && isDriveLetter(rest[0]) && rest[1] == ':' && rest[2] == '\\':
		return rest, nil
	case !relative && nt && len(rest) >= len("Volume{") && strings.EqualFold(rest[:len("Volume{")], "Volume{"):
		return `\\?\` + rest, nil
	}

	return "", fmt.Errorf("it leads to %s, which names neither a drive letter nor a volume of this machine's, and "+
		"may be on another machine, which following it would sign this one in to", target)
}

// isDriveLetter reports whether c is a letter a drive may be named by.
func isDriveLetter(c byte) bool { return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' }

// isUNC reports whether p begins as a UNC path does, with two separators.
func isUNC(p string) bool {
	return len(p) >= 2 && (p[0] == '\\' || p[0] == '/') && (p[1] == '\\' || p[1] == '/')
}

// mountPointData is the reparse data of a junction leading to substitute, an NT path (\??\C:\x,
// \??\Volume{...}\x), shown as display: REPARSE_DATA_BUFFER with a MountPointReparseBuffer -- the
// two names, each counted in bytes without its NUL, in one buffer after the lengths.
func mountPointData(substitute, display string) []byte {
	sub, shown := utf16.Encode([]rune(substitute)), utf16.Encode([]rune(display))

	b := binary.LittleEndian.AppendUint32(nil, reparseTagMountPoint)
	b = binary.LittleEndian.AppendUint16(b, uint16(8+2*(len(sub)+1)+2*(len(shown)+1)))
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint16(b, uint16(2*len(sub)))
	b = binary.LittleEndian.AppendUint16(b, uint16(2*(len(sub)+1)))
	b = binary.LittleEndian.AppendUint16(b, uint16(2*len(shown)))

	for _, c := range append(append(sub, 0), append(shown, 0)...) {
		b = binary.LittleEndian.AppendUint16(b, c)
	}

	return b
}
