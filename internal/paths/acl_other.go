//go:build !windows

package paths

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"syscall"

	"github.com/veil-net/conflux/internal/group"
)

// groupUsers is who a group lets in; a test's stands in for the system's databases.
var groupUsers = group.Users

// Restrict and Trusted are Windows's. Here a mode set on the descriptor and a 0700
// directory that belongs to whoever runs conflux are the whole of it, and secure is
// what makes sure of the second.

// Restrict is a no-op here.
func Restrict(string, bool) error { return nil }

// RestrictToOwner is a no-op here: the mode set on the descriptor is the restriction.
func RestrictToOwner(string, bool) error { return nil }

// Trusted is always true here.
func Trusted(string) bool { return true }

// secure refuses a root another account owns, or a CONFLUX_DIR another account can move,
// and narrows one of conflux's own that something left wider than 0700, or than the 0710
// that lets anchord's account through.
//
// MkdirAll creates at 0700 and leaves a directory that already exists exactly as it
// found it, so without this an /etc/conflux somebody made at 0755 would hold the
// manifest in a traversable directory, and a CONFLUX_DIR another user made would hold
// the binary root runs at boot where that user can replace it. The owner decides, as on
// Windows: one that is not the account running conflux did not get its directory from
// conflux, and whatever it put there is not used. A CONFLUX_DIR is held to its parents
// as well (see parentsAs). Every refusal comes before any change.
func secure(dir string) error { return secureAs(dir, os.Geteuid()) }

// secureAs is secure for a given effective uid, so the refusals can be tested without
// another account.
func secureAs(dir string, euid int) error {
	fi, err := ownedAs(dir, euid)
	if err != nil {
		return err
	}

	if chosen(dir) {
		if err := parentsAs(dir, euid); err != nil {
			return err
		}
	}

	// 0710 -- its group may pass through and list nothing -- is how the supervisor lets
	// anchord's account reach the few things in the state and run directories that anchord
	// runs or reads. ownedBy has just shown the directory to be this account's own, and only
	// its owner can have given it that group and that mode, so it is left as it is.
	if mode := fi.Mode().Perm(); mode == 0o700 || mode == 0o710 {
		return nil
	}

	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("narrow %s to 0700: %w", dir, err)
	}

	return nil
}

// ownedAs is dir as it resolves, once it is shown to be euid's. A root that is a symlink
// is held to the same rule as what it points at: one another account planted would
// otherwise lead straight past the check into a directory of theirs, or of the system's.
func ownedAs(dir string, euid int) (os.FileInfo, error) {
	link, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}

	if err := ownedBy(dir, link, euid); err != nil {
		return nil, err
	}

	if link.Mode()&os.ModeSymlink == 0 {
		return link, nil
	}

	fi, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", dir, err)
	}

	if err := ownedBy(dir, fi, euid); err != nil {
		return nil, err
	}

	return fi, nil
}

// Foreign is what secure would refuse dir with for its owner, before anything is made, or
// nil where dir is this account's or is not there yet. A directory another account made is
// none of conflux's to use, and whoever reads one -- an ephemeral run's root, which /tmp lets
// anybody make first -- holds it to this as the conflux that makes one does.
func Foreign(dir string) error {
	if _, err := os.Lstat(dir); err != nil {
		return nil
	}

	_, err := ownedAs(dir, os.Geteuid())

	return err
}

// parentsAs refuses dir where another account may write a directory above it: one whose
// owner is neither root nor euid, who can always give itself the right, or one that lets
// another account write it (mayWrite). Whoever may write a parent can move dir aside and put a
// directory of their own in its place, with a conflux in it for the boot service to run as
// root. A link on the way is held to the directory it is in, to those above where it leads,
// and to its owner, who may point it elsewhere (ancestors).
func parentsAs(dir string, euid int) error {
	above, err := ancestors(dir)
	if err != nil {
		return err
	}

	for _, p := range above {
		fi, err := os.Lstat(p)
		if err != nil {
			return fmt.Errorf("read %s: %w", p, err)
		}

		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("read the owner of %s: no ownership on this filesystem", p)
		}

		where, who := "inside", ""

		switch {
		case isLink(fi):
			// A link's mode means nothing: who may change it is its owner, and whoever may
			// write the directory it is in, which is checked as one above.
			where = "reached through"

			if int(st.Uid) != 0 && int(st.Uid) != euid {
				who = fmt.Sprintf("belongs to uid %d, who", st.Uid)
			}
		case int(st.Uid) != 0 && int(st.Uid) != euid:
			who = fmt.Sprintf("belongs to uid %d, who", st.Uid)
		default:
			if who, err = mayWrite(p, fi, st.Gid, euid); err != nil {
				return err
			}
		}

		if who != "" {
			return fmt.Errorf("%s is %s %s, which %s could move it aside and put another in its place "+
				"for conflux to run.\n  Choose a CONFLUX_DIR whose every parent only root and uid %d can change, "+
				"or that sits in a sticky directory such as /tmp", dir, where, p, who, euid)
		}
	}

	return nil
}

// mayWrite is who besides root and euid may write the directory p, as a refusal names them,
// or "": see judge, which it hands p's ACL (extendedWriters).
func mayWrite(p string, fi os.FileInfo, gid uint32, euid int) (string, error) {
	acl, aclGroup, err := extendedWriters(p)
	if err != nil {
		return "", fmt.Errorf("read the ACL of %s: %w", p, err)
	}

	return judge(fi.Mode(), gid, acl, aclGroup, euid), nil
}

// judge is who besides root and euid may write a directory of mode and group gid with the ACL
// acl, as a refusal names them, or "": anybody, where its mode or its ACL lets anybody; its
// group, where the mode or the ACL lets the group and the group lets in another account
// (groupOf); a user other than euid, or a group that lets in another account, that its ACL
// names; and any account an ACL names by a UUID alone. aclGroup is an ACL whose mask the mode's
// group bits are (POSIX.1e), which then says what the group may itself. A sticky directory lets
// nobody rename what is not theirs, so what only lets them write it is left out there, as its
// mode's bits are; a right the sticky bit does not hold back is not.
func judge(mode os.FileMode, gid uint32, acl []writer, aclGroup bool, euid int) string {
	sticky := mode&os.ModeSticky != 0

	if !sticky {
		if mode&0o002 != 0 {
			return "anybody may write, and anybody"
		}

		if !aclGroup && mode&0o020 != 0 {
			acl = append([]writer{{who: theGroup}}, acl...)
		}
	}

	for _, w := range acl {
		if sticky && !w.pastSticky {
			continue
		}

		switch {
		case w.who == aUser && int(w.id) != euid && w.id != 0:
			return fmt.Sprintf("its ACL lets uid %d write, and that account", w.id)
		case w.who == aGroup && !groupOf(w.id, euid):
			return fmt.Sprintf("its ACL lets gid %d write, and any account in it", w.id)
		case w.who == theGroup && !groupOf(gid, euid):
			return fmt.Sprintf("its group, gid %d, may write, and any account in it", gid)
		case w.who == everyone:
			return "its ACL lets anybody write, and anybody"
		case w.who == anAccount:
			return fmt.Sprintf("its ACL lets the user or group %s write, and whoever that is", w.uuid)
		}
	}

	return ""
}

// isLink reports whether fi, read without following it, is a link a lookup follows.
func isLink(fi os.FileInfo) bool { return fi.Mode()&os.ModeSymlink != 0 }

// groupOf reports whether the group gid lets in no account but euid's: no member it lists,
// and no account it is the primary group of, but that one -- a group of one user, as Ubuntu
// gives each, whose write on a directory is that user's alone. Where the group, the account
// or who the group lets in cannot be read, it does not.
func groupOf(gid uint32, euid int) bool {
	g, err := user.LookupGroupId(strconv.FormatUint(uint64(gid), 10))
	if err != nil {
		return false
	}

	me, err := user.LookupId(strconv.Itoa(euid))
	if err != nil {
		return false
	}

	users, err := groupUsers(g.Name, g.Gid)
	if err != nil {
		return false
	}

	for _, u := range users {
		if u != me.Username {
			return false
		}
	}

	return true
}

func ownedBy(dir string, fi os.FileInfo, euid int) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("read the owner of %s: no ownership on this filesystem", dir)
	}

	switch owner := int(st.Uid); {
	case owner == euid:
		return nil
	case owner == 0:
		return fmt.Errorf("%s belongs to root, and conflux is not running as root.\n"+
			"  Run this again as root", dir)
	default:
		return fmt.Errorf(
			"%s belongs to uid %d and conflux runs as uid %d, so conflux did not create it and will not "+
				"use what is in it.\n  Remove it, then run this again", dir, owner, euid)
	}
}
