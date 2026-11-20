package paths

import (
	"encoding/binary"
	"errors"
	"unsafe"

	"golang.org/x/sys/unix"
)

// FreeBSD's acl_type_t for an access ACL and an NFSv4 one.
const (
	aclTypeAccess = 2
	aclTypeNFS4   = 4
)

// rootACLMayRefuse is whether a root's own ACL can refuse it once secure has narrowed it: here
// an NFSv4 ACL sits beside the mode and keeps what chmod does not rewrite (judgeRoot).
const rootACLMayRefuse = true

// extendedWriters is who p's ACL lets write it besides its owner and everybody, and whether the
// ACL rather than the mode says what its group may: here the NFSv4 ACL a filesystem keeps them
// in (ZFS, UFS with nfsv4acls), which sits beside the mode, or else the POSIX.1e access ACL
// (UFS with acls), whose mask the mode's group bits are. They are asked of __acl_get_link, for
// p itself, or of __acl_get_fd, where fd is open on p, by the call's number: x/sys/unix wraps
// neither. A filesystem refuses the kind it does not keep with EINVAL, and one that keeps neither
// refuses both, with EINVAL or EOPNOTSUPP, and has none.
func extendedWriters(p string, fd int) ([]writer, bool, error) {
	call, of := uintptr(unix.SYS___ACL_GET_FD), uintptr(fd)

	if fd < 0 {
		name, err := unix.BytePtrFromString(p)
		if err != nil {
			return nil, false, err
		}

		call, of = unix.SYS___ACL_GET_LINK, uintptr(unsafe.Pointer(name))
	}

	for _, kind := range []int{aclTypeNFS4, aclTypeAccess} {
		b := make([]byte, freebsdACLSize)
		binary.NativeEndian.PutUint32(b, freebsdMaxEntries)

		_, _, errno := unix.Syscall(call, of, uintptr(kind), uintptr(unsafe.Pointer(&b[0])))

		switch {
		case errno == 0:
			ws, err := freebsdACL(b, kind == aclTypeNFS4)

			return ws, kind == aclTypeAccess, err
		case !errors.Is(errno, unix.EINVAL) && !errors.Is(errno, unix.EOPNOTSUPP):
			return nil, false, errno
		}
	}

	return nil, false, nil
}
