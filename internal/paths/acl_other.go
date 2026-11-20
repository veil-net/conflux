//go:build !windows

package paths

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"syscall"

	"golang.org/x/sys/unix"

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

// aLink is what makeWay calls a link made where it was making a directory.
const aLink = "a link"

// step is a directory or a link a walk holds: open as itself on fd, or, where it is a link, or a
// directory this account may search and not read (holdDir), by its name, rel, in the directory fd is
// open on, which the walk holds too; with what fstat said of it as the walk met it.
type step struct {
	fd  int
	rel string
	st  unix.Stat_t
}

// at is name in the directory s is, as an *at call on s.fd takes it.
func (s step) at(name string) string {
	if s.rel == "" {
		return name
	}

	return s.rel + "/" + name
}

// close lets s go: its descriptor, where it has one of its own.
func (s step) close() {
	if s.rel == "" {
		unix.Close(s.fd)
	}
}

// openTop holds / open.
func openTop(string) (step, error) {
	s, err := opened(unix.AT_FDCWD, "/")
	if err != nil {
		return step{}, &os.PathError{Op: "open", Path: "/", Err: err}
	}

	return s, nil
}

// lookUp is what is at name in the directory parent is, and whether it is a link: a directory, held
// open as itself (opened), or by its name where this account may search it and not read it; or a
// link, by its name, never followed. Anything else at the name is refused, and nothing at it is an
// error that is fs.ErrNotExist. What fstatat reads of the name, once the open has refused it, is
// what is there by then: the directory parent is has been judged, and only root and this account
// may change what is in it -- or, in a sticky one, whoever owns that name.
func lookUp(parent step, name string) (step, bool, error) {
	at := parent.at(name)

	s, err := opened(parent.fd, at)
	if err == nil || errors.Is(err, unix.ENOENT) {
		return s, false, err
	}

	byName := step{fd: parent.fd, rel: at}
	if err := ignoringEINTR(func() error {
		return unix.Fstatat(parent.fd, at, &byName.st, unix.AT_SYMLINK_NOFOLLOW)
	}); err != nil {
		return step{}, false, err
	}

	switch byName.st.Mode & unix.S_IFMT {
	case unix.S_IFLNK:
		return byName, true, nil
	case unix.S_IFDIR:
		if errors.Is(err, unix.EACCES) {
			return byName, false, nil
		}
	}

	return step{}, false, err
}

// opened is the directory name, in the one dirfd is open on, held open as itself (holdDir): a link
// at the name is refused rather than followed.
func opened(dirfd int, name string) (step, error) {
	var s step

	if err := ignoringEINTR(func() (err error) {
		s.fd, err = unix.Openat(dirfd, name, holdDir|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)

		return err
	}); err != nil {
		return step{}, err
	}

	if err := unix.Fstat(s.fd, &s.st); err != nil {
		unix.Close(s.fd)

		return step{}, err
	}

	return s, nil
}

// readLink is where the link s leads, read where the walk holds it.
func readLink(s step) (string, error) {
	for size := 256; ; size *= 2 {
		b := make([]byte, size)

		var n int
		if err := ignoringEINTR(func() (err error) {
			n, err = unix.Readlinkat(s.fd, s.rel, b)

			return err
		}); err != nil {
			return "", err
		}

		if n < size {
			return string(b[:n]), nil
		}
	}
}

// makeStep makes the directory name, at 0700, in the one parent is (mkdirat), and holds nothing:
// makeWay goes into it as a walk would (lookUp). The root is made as any other.
func makeStep(parent step, name string, _ bool) (step, bool, error) {
	return step{}, false, ignoringEINTR(func() error { return unix.Mkdirat(parent.fd, parent.at(name), 0o700) })
}

// ignoringEINTR is f, again for as long as a signal interrupts it, as the os package retries its
// own calls.
func ignoringEINTR(f func() error) error {
	for {
		if err := f(); !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

// parentsRule is parents' rule for dir, for the account this process runs as (parentsRuleAs).
func parentsRule(dir string) judgement { return parentsRuleAs(dir, os.Geteuid()) }

// parentsRuleAs is parents' rule for dir, for euid: a directory on the way to it is refused where
// another account may write it -- one whose owner is neither root nor euid, who can always give
// itself the right, or one whose mode or ACL lets another account write it (writerOf) -- and a link
// where another account owns it, who may point it elsewhere: its mode means nothing, and whoever may
// write the directory it is in is held as one above. Whoever may write a directory above dir can
// move dir aside and put a directory of their own in its place, with a conflux in it for the boot
// service to run as root. Owner, group and mode are as fstat read them where the walk met each one;
// a directory's ACL is read at its path, which leads through directories already judged, and so
// only root and euid may change where it leads.
func parentsRuleAs(dir string, euid int) judgement {
	return func(p string, s step, link bool) error {
		where := "inside"
		if link {
			where = "reached through"
		}

		mode := os.FileMode(s.st.Mode & 0o777)
		if s.st.Mode&unix.S_ISVTX != 0 {
			mode |= os.ModeSticky
		}

		who, err := writerOf(p, s.st.Uid, s.st.Gid, mode, link, euid)
		if err == nil && who != "" {
			err = parentRefusal(dir, where, p, who, euid)
		}

		return err
	}
}

// secure refuses a root another account owns, or whose extended ACL lets another account write
// or move it, or a CONFLUX_DIR another account can move, and narrows one of conflux's own that
// something left wider than 0700, or than the 0710 that lets anchord's account through.
//
// makeRoot creates at 0700 and leaves a directory that already exists exactly as it
// found it, so without this an /etc/conflux somebody made at 0755 would hold the
// manifest in a traversable directory, and a CONFLUX_DIR another user made would hold
// the binary root runs at boot where that user can replace it. The owner decides, as on
// Windows: one that is not the account running conflux did not get its directory from
// conflux, and whatever it put there is not used. A CONFLUX_DIR is held to its parents
// first (see parentsAs), before anything at its name is read. Every refusal comes before secure
// changes anything; a root that was not there EnsureAll has made by then, and a refusal leaves
// it, empty and this account's.
func secure(dir string) error { return secureAs(dir, os.Geteuid()) }

// secureAs is secure for a given effective uid, so the refusals can be tested without
// another account.
func secureAs(dir string, euid int) error {
	if chosen(dir) {
		if err := parentsAs(dir, euid); err != nil {
			return err
		}
	}

	link, fi, err := ownedAs(dir, euid, ownedBy)
	if err != nil {
		return err
	}

	// The root's own ACL, judged as the root will be once narrowed below: 0700, or a 0710 whose
	// group writes nothing either, and no sticky bit to let anything through. A directory above
	// passes an entry on to what is made inside it, so one lands on the root whether or not that
	// directory was let through itself -- a sticky one, or one above a root that is not a
	// CONFLUX_DIR. An extended ACL (macOS's, FreeBSD's NFSv4) sits beside the mode and keeps
	// it through the narrowing, so it is refused, but for the NFSv4 entries that are the mode
	// itself, which chmod rewrites (judgeRoot); a POSIX.1e ACL's mask is the mode's group bits,
	// which the narrowing takes every entry's write away with (judge), so where every ACL is one
	// of those, or there is none, it is not read (rootACLMayRefuse). A link's own ACL says
	// nothing, so it is read where the link leads.
	if rootACLMayRefuse {
		acl := dir
		if isLink(link) {
			if acl, err = filepath.EvalSymlinks(dir); err != nil {
				return fmt.Errorf("read %s: %w", dir, err)
			}
		}

		writers, aclGroup, err := aclOf(acl)
		if err != nil {
			return err
		}

		if who := judgeRoot(fi.Mode(), fi.Sys().(*syscall.Stat_t).Gid, writers, aclGroup, euid); who != "" {
			return fmt.Errorf("%s is not conflux's alone: %s could put what it likes in it, or move it aside, "+
				"for conflux to run.\n  Remove that entry from its ACL, and from the directory above that passed "+
				"it on, if one did; then run this again", dir, who)
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

// ownedAs is what Lstat says of dir, and what dir resolves to, the same where it is not a link,
// once owns has held each to euid: secure's rule (ownedBy) or a reader's (readerOwns). A root that
// is a symlink is held to the same rule as what it points at: one another account planted would
// otherwise lead straight past the check into a directory of theirs, or of the system's.
func ownedAs(dir string, euid int, owns func(string, os.FileInfo, int) error) (link, fi os.FileInfo, err error) {
	if link, err = os.Lstat(dir); err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", dir, err)
	}

	if err := owns(dir, link, euid); err != nil {
		return nil, nil, err
	}

	if !isLink(link) {
		return link, link, nil
	}

	if fi, err = os.Stat(dir); err != nil {
		return nil, nil, fmt.Errorf("read %s: %w", dir, err)
	}

	if err := owns(dir, fi, euid); err != nil {
		return nil, nil, err
	}

	return link, fi, nil
}

// checkRoot is Check's judgement of the root dir: checkRootAs for this process's effective uid.
func checkRoot(dir string) error { return checkRootAs(dir, os.Geteuid()) }

// contents is nothing here: what a root holds is judged by the root's own mode and ACL, which
// checkRoot holds to letting nobody else write it, and nothing in it is another account's unless
// one could.
func contents(string) error { return nil }

// checkRootAs refuses the root dir, for a command run as euid about to read what is in it by name,
// where another account could have put something there: one owned, or reached through a link
// owned, by an account other than root and euid (ownedAs, readerOwns), or whose mode or ACL, as
// found, lets another account write it (judge), the sticky bit letting nothing through, since a
// name not taken yet is anybody's in a sticky directory. A CONFLUX_DIR is held to its parents first
// (parentsAs). Nothing is narrowed, as secure would narrow it: a reader changes nothing.
func checkRootAs(dir string, euid int) error {
	if chosen(dir) {
		if err := parentsAs(dir, euid); err != nil {
			return err
		}
	}

	link, fi, err := ownedAs(dir, euid, readerOwns)
	if err != nil {
		return err
	}

	acl := dir
	if isLink(link) {
		if acl, err = filepath.EvalSymlinks(dir); err != nil {
			return fmt.Errorf("read %s: %w", dir, err)
		}
	}

	writers, aclGroup, err := aclOf(acl)
	if err != nil {
		return err
	}

	if who := judge(fi.Mode()&^os.ModeSticky, fi.Sys().(*syscall.Stat_t).Gid, writers, aclGroup, euid); who != "" {
		return fmt.Errorf("%s is not conflux's alone: %s could put what it likes in it for conflux to read or "+
			"run, so conflux will not use it.\n  Narrow it to 0700, and remove that entry from its ACL; then run "+
			"this again", dir, who)
	}

	return nil
}

// readerOwns refuses dir, of which fi is what Lstat or Stat said, where it belongs to an account
// other than root and euid: one root's is root's to have made, and a reader trusts it as it trusts
// root.
func readerOwns(dir string, fi os.FileInfo, euid int) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("read the owner of %s: no ownership on this filesystem", dir)
	}

	if owner := int(st.Uid); owner != 0 && owner != euid {
		return fmt.Errorf("%s belongs to uid %d, not to root or uid %d, which conflux runs as, so conflux did not "+
			"create it and will not use what is in it.\n  Remove it, then run this again", dir, owner, euid)
	}

	return nil
}

// parentsAs refuses dir where its way, walked from / (walk), is not there, or is not held to
// parents' rule for euid (parentsRuleAs).
func parentsAs(dir string, euid int) error { return judgeWay(dir, parentsRuleAs(dir, euid)) }

// writerOf is who besides root and euid may move what is in p, a directory or a link on the way to
// a root owned by uid, of group gid and at mode, as a refusal names them, or "": its owner, where
// that is neither, or, for a directory, anybody its mode or ACL lets write it (judge). A link's mode
// means nothing.
func writerOf(p string, uid, gid uint32, mode os.FileMode, link bool, euid int) (string, error) {
	switch {
	case int(uid) != 0 && int(uid) != euid:
		return fmt.Sprintf("belongs to uid %d, who", uid), nil
	case link:
		return "", nil
	}

	acl, aclGroup, err := aclOf(p)
	if err != nil {
		return "", err
	}

	return judge(mode, gid, acl, aclGroup, euid), nil
}

// parentRefusal is the refusal of dir for p, a directory it is where of (inside, or reached
// through), which who could change.
func parentRefusal(dir, where, p, who string, euid int) error {
	return fmt.Errorf("%s is %s %s, which %s could move it aside and put another in its place "+
		"for conflux to run.\n  Choose a CONFLUX_DIR whose every parent only root and uid %d can change, "+
		"or that sits in a sticky directory such as /tmp", dir, where, p, who, euid)
}

// aclOf is who p's ACL lets write it, and whether that ACL says what p's group may
// (extendedWriters), for judge, or judgeRoot, to hold beside p's mode; a failure names p.
func aclOf(p string) ([]writer, bool, error) {
	acl, aclGroup, err := extendedWriters(p)
	if err != nil {
		return nil, false, fmt.Errorf("read the ACL of %s: %w", p, err)
	}

	return acl, aclGroup, nil
}

// judgeRoot is who besides root and euid may write a root found at mode, of group gid, with the ACL
// acl, once secure has narrowed it: judge at 0700. An NFSv4 ACL entry that is a write bit the mode
// found shows (writer.modeBit) is the mode, and chmod rewrites it with the mode, so it is the
// narrowing's to take away, as a POSIX.1e ACL's write is; any other entry is judged.
func judgeRoot(mode os.FileMode, gid uint32, acl []writer, aclGroup bool, euid int) string {
	acl = slices.DeleteFunc(acl, func(w writer) bool { return mode&w.modeBit != 0 })

	return judge(0o700, gid, acl, aclGroup, euid)
}

// judge is who besides root and euid may write a directory of mode and group gid with the ACL
// acl, as a refusal names them, or "": anybody, where its mode or its ACL lets anybody; its
// group, where the mode or the ACL lets the group and the group lets in another account
// (groupOf); a user other than euid, or a group that lets in another account, that its ACL
// names; and any account an ACL names by a UUID alone. aclGroup is an ACL whose mask the mode's
// group bits are (POSIX.1e), which then says what the group may itself, and lets nobody write
// where those bits do not: a directory's own are its mask already, and a root judged as secure
// narrows it is judged at the mask the narrowing gives it. A sticky directory lets nobody
// rename what is not theirs, so what only lets them write it is left out there, as its mode's
// bits are; a right the sticky bit does not hold back is not.
func judge(mode os.FileMode, gid uint32, acl []writer, aclGroup bool, euid int) string {
	if aclGroup && mode&0o020 == 0 {
		acl = nil
	}

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
