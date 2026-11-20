package paths

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"unicode/utf16"
)

// symlinkData is the reparse data of a symbolic link naming substitute, shown as display, relative
// to the folder it is in where relative: REPARSE_DATA_BUFFER with a SymbolicLinkReparseBuffer, as
// CreateSymbolicLink writes it -- the names' lengths, the flags, then both names, without NULs.
func symlinkData(substitute, display string, relative bool) []byte {
	sub, shown := utf16.Encode([]rune(substitute)), utf16.Encode([]rune(display))

	flags := uint32(0)
	if relative {
		flags = symlinkFlagRelative
	}

	b := binary.LittleEndian.AppendUint32(nil, reparseTagSymlink)
	b = binary.LittleEndian.AppendUint16(b, uint16(12+2*len(sub)+2*len(shown)))
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint16(b, uint16(2*len(sub)))
	b = binary.LittleEndian.AppendUint16(b, uint16(2*len(sub)))
	b = binary.LittleEndian.AppendUint16(b, uint16(2*len(shown)))
	b = binary.LittleEndian.AppendUint32(b, flags)

	for _, c := range append(sub, shown...) {
		b = binary.LittleEndian.AppendUint16(b, c)
	}

	return b
}

// TestWindowsLinkTarget: a symbolic link's or a junction's target is read from its reparse data as
// os.Readlink names it -- by its drive letter or its volume's GUID, or as a relative link writes it
// -- and one that may be another machine's, a share by its UNC path or a WebDAV server's, or a
// device by its NT name, or a relative one naming a volume of its own, as filepath.VolumeName reads
// one in either separator -- a UNC, device or NT path, or a drive -- is refused, naming it. A reparse
// point of another kind is no link, and data in no shape a file system returns is refused.
func TestWindowsLinkTarget(t *testing.T) {
	const volume = `\??\Volume{6a2f4c1e-0b7d-4e55-9c3a-2f1d8e7b6a90}\conflux`

	for _, c := range []struct {
		name, want string
		data       []byte
	}{
		{"a junction to a drive", `D:\conflux`, mountPointData(`\??\D:\conflux`, `D:\conflux`)},
		{"a junction to a volume's GUID", `\\?\Volume{6a2f4c1e-0b7d-4e55-9c3a-2f1d8e7b6a90}\conflux`,
			mountPointData(volume, "")},
		{"a link to a drive", `c:\conflux`, symlinkData(`\??\c:\conflux`, `c:\conflux`, false)},
		{"a relative link", `..\conflux`, symlinkData(`..\conflux`, `..\conflux`, true)},
		{"a relative link from the top of its volume", `\conflux`, symlinkData(`\conflux`, `\conflux`, true)},
	} {
		if got, err := windowsLinkTarget(c.data); err != nil || got != c.want {
			t.Errorf("%s: windowsLinkTarget = %q, %v, want %q", c.name, got, err, c.want)
		}
	}

	for _, c := range []struct {
		name, target string
		data         []byte
	}{
		{"a link to a share", `\??\UNC\192.0.2.1\share\conflux`,
			symlinkData(`\??\UNC\192.0.2.1\share\conflux`, `\\192.0.2.1\share\conflux`, false)},
		{"a link to a WebDAV server", `\??\UNC\dav.example@SSL\DavWWWRoot\conflux`,
			symlinkData(`\??\UNC\dav.example@SSL\DavWWWRoot\conflux`, `\\dav.example@SSL\DavWWWRoot\conflux`, false)},
		{"a junction to a share", `\??\UNC\192.0.2.1\share`, mountPointData(`\??\UNC\192.0.2.1\share`, "")},
		{"a link to the UNC provider by its NT name", `\??\GLOBALROOT\Device\Mup\192.0.2.1\share`,
			symlinkData(`\??\GLOBALROOT\Device\Mup\192.0.2.1\share`, "", false)},
		{"a link to a device", `\Device\Mup\192.0.2.1\share`, symlinkData(`\Device\Mup\192.0.2.1\share`, "", false)},
		{"a link to a drive's device", `\??\C:`, symlinkData(`\??\C:`, "", false)},
		{"a relative link written as a UNC path", `\\192.0.2.1\share`, symlinkData(`\\192.0.2.1\share`, "", true)},
		{"a relative link written as a UNC path, separators mixed", `/\192.0.2.1\share`,
			symlinkData(`/\192.0.2.1\share`, "", true)},
		{"a relative link written as an NT path", `\??\UNC\192.0.2.1\share\conflux`,
			symlinkData(`\??\UNC\192.0.2.1\share\conflux`, "", true)},
		{"a relative link written as an NT path with slashes", `/??/UNC/192.0.2.1/share/conflux`,
			symlinkData(`/??/UNC/192.0.2.1/share/conflux`, "", true)},
		{"a relative link written as an NT path, separators mixed", `\??/UNC/192.0.2.1/share`,
			symlinkData(`\??/UNC/192.0.2.1/share`, "", true)},
		{"a relative link written as the NT namespace alone", `\??`, symlinkData(`\??`, "", true)},
		{"a relative link written as a local device path", `\\.\UNC\192.0.2.1\share`,
			symlinkData(`\\.\UNC\192.0.2.1\share`, "", true)},
		{"a relative link written as a local device path with slashes", `//./UNC/192.0.2.1/share`,
			symlinkData(`//./UNC/192.0.2.1/share`, "", true)},
		{"a relative link written as a root local device path", `\\?\UNC\192.0.2.1\share`,
			symlinkData(`\\?\UNC\192.0.2.1\share`, "", true)},
		{"a relative link written with a drive", `Z:\conflux`, symlinkData(`Z:\conflux`, "", true)},
		{"a relative link written relative to a drive", `Z:conflux`, symlinkData(`Z:conflux`, "", true)},
	} {
		got, err := windowsLinkTarget(c.data)
		if err == nil || !strings.Contains(err.Error(), c.target) || !strings.Contains(err.Error(), "another machine") {
			t.Errorf("%s: windowsLinkTarget = %q, %v, want a refusal naming %s and another machine", c.name, got, err,
				c.target)
		}
	}

	socket := []byte{0x23, 0, 0, 0x80, 0, 0, 0, 0} // IO_REPARSE_TAG_AF_UNIX, holding nothing
	if _, err := windowsLinkTarget(socket); !errors.Is(err, errNotLink) {
		t.Errorf("windowsLinkTarget(an AF_UNIX socket's) = %v, want %v", err, errNotLink)
	}

	whole := symlinkData(`\??\C:\conflux`, "", false)
	for _, b := range [][]byte{nil, whole[:6], whole[:len(whole)-2], whole[:16]} {
		if _, err := windowsLinkTarget(b); !errors.Is(err, errReparse) {
			t.Errorf("windowsLinkTarget(% x) = %v, want %v", b, err, errReparse)
		}
	}
}
