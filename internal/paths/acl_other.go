//go:build !windows

package paths

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/veil-net/conflux/internal/group"
)

// groups answers who a group lets in: one group.Lookup for the whole process, so that each group's
// record and the account database are read at most once, however many roots and ways it judges -- a
// walk of a CONFLUX_DIR's parents asks of each one its group may write. A supervisor judges its roots
// as it starts, once in its process, and every other command is over long before a group's members
// change under it. A test sets its own: a new Lookup, to read afresh, or one standing in for the
// system's databases.
var groups usersOf = new(group.Lookup)

// usersOf is what groups is: who the group of that name, whose id is gid, lets in.
type usersOf interface {
	Users(name, gid string) ([]string, error)
}

// Restrict and Trusted are Windows's. Here a mode set on the descriptor and a 0700
// directory that belongs to whoever runs conflux are the whole of it, and EnsureAll is
// what makes sure of the second.

// Restrict is a no-op here.
func Restrict(string, bool) error { return nil }

// RestrictToOwner is a no-op here: the mode set on the descriptor is the restriction.
func RestrictToOwner(string, bool) error { return nil }

// ours is why the directory s holds, at the root dir's name, is not as conflux makes a root, or "" where
// it is: owned by root or the account running conflux, and written by nobody else, by its mode -- the
// sticky bit letting nothing through, since a name not taken yet is anybody's in a sticky directory --
// or its ACL (judge), as fstat read it where the walk met it and its ACL at dir. A 0710 the supervisor
// gives the state and run directories, so that anchord's account may pass through them, lets that
// account write nothing. installation is Windows's, where an installation's root is judged for the
// SYSTEM service; here the service runs as root, as every command that makes such a root does.
func ours(dir string, s step, _ bool) (string, error) {
	euid := os.Geteuid()

	if owner := int(s.st.Uid); owner != 0 && owner != euid {
		return fmt.Sprintf("uid %d owns it", owner), nil
	}

	acl, aclGroup, err := aclOf(dir)
	if err != nil {
		return "", err
	}

	if who := judge(os.FileMode(s.st.Mode&0o777), s.st.Gid, acl, aclGroup, euid); who != "" {
		return who + " could put what they like in it", nil
	}

	return "", nil
}

// ElevatedDefaultOwner is a no-op here: what conflux makes is the account's that makes it, root's
// for an installation's root, which every command making it runs as.
func ElevatedDefaultOwner() error { return nil }

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
// link, by its name, never followed. Anything else at the name is refused, by the type fstatat reads of it
// and not by the error the open failed with -- which for a socket is EOPNOTSUPP on macOS and OpenBSD --
// as errNotDir, and nothing at it is an error that is fs.ErrNotExist. What fstatat reads of the name, once the open has refused it, is
// what is there by then: on a way the walk judges, the directory parent is has been judged, and only
// root and this account may change what is in it -- or, in a sticky one, whoever owns that name; on
// one it does not, a platform root's, which only root, or the user it is for, may change, it is the
// lookup by name any program makes there.
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

		return step{}, false, err
	}

	return step{}, false, errNotDir
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
func makeStep(parent step, name string) (step, bool, error) {
	return step{}, false, ignoringEINTR(func() error { return unix.Mkdirat(parent.fd, parent.at(name), 0o700) })
}

// removeFrom is RemoveRoot's, ownFolder's and RemoveWay's removal of name, in the directory parent is,
// which p names (removeAt), and whether anything was there.
func removeFrom(parent step, name, p string) (bool, error) {
	switch err := removeAt(parent.fd, parent.at(name), p); {
	case errors.Is(err, unix.ENOENT):
		return false, nil
	case err != nil:
		return true, err
	}

	return true, nil
}

// removeAt removes at, in the directory dirfd is open on, which p names, and, where it is a directory,
// all it holds first: what fstatat says of the name, never followed; a directory opened there with
// O_NOFOLLOW and held to what fstatat said, what it holds removed through it, then the directory by
// unlinkat; anything else, a link among it, unlinked as itself. Something gone since its directory was
// listed is passed over; nothing at at itself is an error that is ENOENT.
func removeAt(dirfd int, at, p string) error {
	var st unix.Stat_t
	if err := ignoringEINTR(func() error { return unix.Fstatat(dirfd, at, &st, unix.AT_SYMLINK_NOFOLLOW) }); err != nil {
		return &os.PathError{Op: "stat", Path: p, Err: err}
	}

	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		if err := ignoringEINTR(func() error { return unix.Unlinkat(dirfd, at, 0) }); err != nil {
			return &os.PathError{Op: "remove", Path: p, Err: err}
		}

		return nil
	}

	var fd int
	if err := ignoringEINTR(func() (err error) {
		fd, err = unix.Openat(dirfd, at, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)

		return err
	}); err != nil {
		return &os.PathError{Op: "open", Path: p, Err: err}
	}
	defer unix.Close(fd)

	var held unix.Stat_t
	if err := unix.Fstat(fd, &held); err != nil {
		return &os.PathError{Op: "stat", Path: p, Err: err}
	}

	if held.Dev != st.Dev || held.Ino != st.Ino {
		return fmt.Errorf("%s changed while conflux removed it.\n  Run this again", p)
	}

	names, err := namesIn(fd)
	if err != nil {
		return &os.PathError{Op: "read", Path: p, Err: err}
	}

	for _, name := range names {
		if err := removeAt(fd, name, filepath.Join(p, name)); err != nil && !errors.Is(err, unix.ENOENT) {
			return err
		}
	}

	if err := ignoringEINTR(func() error { return unix.Unlinkat(dirfd, at, unix.AT_REMOVEDIR) }); err != nil {
		return &os.PathError{Op: "remove", Path: p, Err: err}
	}

	return nil
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

// serviceRule is parents' rule for dir as the boot service holds it at every start: root's, which
// here is the account every command that makes an installation's root runs as, since each of them
// needs root -- parentsRule's.
func serviceRule(dir string) judgement { return parentsRule(dir) }

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

// namesIn is what the directory fd holds open, freshly, lists, "." and ".." aside.
func namesIn(fd int) ([]string, error) {
	var names []string

	b := make([]byte, 8192)

	for {
		var n int
		if err := ignoringEINTR(func() (err error) {
			n, err = unix.ReadDirent(fd, b)

			return err
		}); err != nil {
			return nil, err
		}

		if n <= 0 {
			return names, nil
		}

		_, _, names = unix.ParseDirent(b[:n], -1, names)
	}
}

// openIn opens name, a file in the directory s holds, which p names, as OpenUntrusted opens one: looked
// up there and nowhere else (openat), never followed.
func openIn(s step, name, p string) (*os.File, error) {
	var fd int
	if err := ignoringEINTR(func() (err error) {
		fd, err = unix.Openat(s.fd, s.at(name), OpenUntrusted|unix.O_CLOEXEC, 0)

		return err
	}); err != nil {
		return nil, &os.PathError{Op: "open", Path: p, Err: err}
	}

	return os.NewFile(uintptr(fd), p), nil
}

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
// (extendedWriters), for judge to hold beside p's mode: read at p, never followed; a failure names p.
func aclOf(p string) ([]writer, bool, error) {
	acl, aclGroup, err := extendedWriters(p)
	if err != nil {
		return nil, false, fmt.Errorf("read the ACL of %s: %w", p, err)
	}

	return acl, aclGroup, nil
}

// judge is who besides root and euid may write a directory of mode and group gid with the ACL
// acl, as a refusal names them, or "": anybody, where its mode or its ACL lets anybody; its
// group, where the mode or the ACL lets the group and the group lets in another account
// (groupOf); a user other than euid, or a group that lets in another account, that its ACL
// names; and any account an ACL names by a UUID alone. aclGroup is an ACL whose mask the mode's
// group bits are (POSIX.1e), which then says what the group may itself, and lets nobody write
// where those bits do not: a directory's own are its mask already. A sticky directory lets nobody
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

	users, err := groups.Users(g.Name, g.Gid)
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
