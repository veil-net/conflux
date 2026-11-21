package paths

import (
	"errors"

	"golang.org/x/sys/unix"
)

// posixACLName is the extended attribute Linux keeps a POSIX.1e access ACL in.
const posixACLName = "system.posix_acl_access"

// extendedWriters is who p's ACL lets write it besides its owner and everybody, and whether
// the ACL rather than the mode says what its group may: here a POSIX.1e access ACL, whose
// mask the mode's group bits are once there is one. A filesystem that keeps none has none. It is
// read at p, never followed.
func extendedWriters(p string) ([]writer, bool, error) {
	get := func(b []byte) (int, error) { return unix.Lgetxattr(p, posixACLName, b) }

	for {
		n, err := get(nil)
		if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.EOPNOTSUPP) {
			return nil, false, nil
		}

		if err != nil {
			return nil, false, err
		}

		b := make([]byte, n)

		n, err = get(b)
		if errors.Is(err, unix.ERANGE) {
			continue // it grew since it was measured
		}

		if err != nil {
			return nil, false, err
		}

		entries, err := linuxACL(b[:n])
		if err != nil {
			return nil, false, err
		}

		return posixWriters(entries), true, nil
	}
}
