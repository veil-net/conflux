package paths

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// rootACLMayRefuse is whether a root's own ACL can refuse it once secure has narrowed it: here
// the extended ACL sits beside the mode and keeps every entry through the narrowing.
const rootACLMayRefuse = true

// extendedWriters is who p's ACL lets write it besides its owner and everybody, and whether the
// ACL rather than the mode says what its group may: here macOS's extended ACL, which sits beside
// the mode, so the mode's group bits still count. It is asked of getattrlist, for
// ATTR_CMN_EXTENDED_SECURITY of p itself, by the call's number: x/sys/unix does not wrap it.
// 4 KiB holds the largest ACL macOS keeps, of 128 entries.
func extendedWriters(p string) ([]writer, bool, error) {
	name, err := unix.BytePtrFromString(p)
	if err != nil {
		return nil, false, err
	}

	attrs := unix.Attrlist{Bitmapcount: unix.ATTR_BIT_MAP_COUNT, Commonattr: unix.ATTR_CMN_EXTENDED_SECURITY}
	b := make([]byte, 4096)

	//lint:ignore SA1019 x/sys/unix has no libSystem wrapper for getattrlist, and cgo is not used
	if _, _, errno := unix.Syscall6(unix.SYS_GETATTRLIST, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&attrs)),
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)), unix.FSOPT_NOFOLLOW, 0); errno != 0 {
		return nil, false, errno
	}

	ws, err := kauthAttr(b)

	return ws, false, err
}
