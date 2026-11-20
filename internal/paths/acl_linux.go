package paths

import (
	"errors"

	"golang.org/x/sys/unix"
)

// posixACLName is the extended attribute Linux keeps a POSIX.1e access ACL in.
const posixACLName = "system.posix_acl_access"

// rootACLMayRefuse is whether a root's own ACL can refuse it once secure has narrowed it: not
// here, where every ACL extendedWriters reads is a POSIX.1e one, whose mask is the mode's group
// bits, which the narrowing to 0700 empties (judge). So the read is left out, while the reader
// reports every ACL it returns as POSIX.1e (TestARootsACLIsLeftUnreadOnlyBesideAPOSIXReader).
const rootACLMayRefuse = false

// extendedWriters is who p's ACL lets write it besides its owner and everybody, and whether
// the ACL rather than the mode says what its group may: here a POSIX.1e access ACL, whose
// mask the mode's group bits are once there is one. A filesystem that keeps none has none.
func extendedWriters(p string) ([]writer, bool, error) {
	for {
		n, err := unix.Lgetxattr(p, posixACLName, nil)
		if errors.Is(err, unix.ENODATA) || errors.Is(err, unix.EOPNOTSUPP) {
			return nil, false, nil
		}

		if err != nil {
			return nil, false, err
		}

		b := make([]byte, n)

		n, err = unix.Lgetxattr(p, posixACLName, b)
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
