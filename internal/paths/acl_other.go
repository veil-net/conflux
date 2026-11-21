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
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"

	"github.com/veil-net/conflux/internal/group"
	"github.com/veil-net/conflux/internal/privcheck"
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
// directory that belongs to whoever runs conflux are the whole of it, and secure is
// what makes sure of the second.

// Restrict is a no-op here.
func Restrict(string, bool) error { return nil }

// RestrictToOwner is a no-op here: the mode set on the descriptor is the restriction.
func RestrictToOwner(string, bool) error { return nil }

// remakeOld is a no-op here: what root or the account running conflux owns passes secure, and the
// service runs as root, as every command that makes an installation's root does, so nothing an
// older conflux made fails the rule that it would make again.
func remakeOld(Dirs, string) ([]string, error) { return nil, nil }

// makeInside makes dir, a root of d's inside another, where it is not there yet. RemakeOld keeps no
// log here, having nothing to remove, so there is none to move back.
func (Dirs) makeInside(dir string) error { return os.MkdirAll(dir, 0o700) }

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

// removeFrom is RemoveRoot's removal of name, in the directory parent is, which p names (removeAt),
// and whether anything was there.
func removeFrom(parent step, name, p string) (bool, error) {
	switch err := removeAt(parent.fd, parent.at(name), p); {
	case errors.Is(err, unix.ENOENT):
		return false, nil
	case err != nil:
		return true, err
	}

	return true, nil
}

// listing is the directory s holds, which p names, opened again through s, by no name, to be listed
// (namesIn).
func listing(s step, p string) (int, error) {
	var fd int
	if err := ignoringEINTR(func() (err error) {
		fd, err = unix.Openat(s.fd, s.at("."), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)

		return err
	}); err != nil {
		return -1, &os.PathError{Op: "open", Path: p, Err: err}
	}

	return fd, nil
}

// namesOf is what the directory s holds, which p names, lists, read through s (listing).
func namesOf(s step, p string) ([]string, error) {
	fd, err := listing(s, p)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)

	names, err := namesIn(fd)
	if err != nil {
		return nil, &os.PathError{Op: "read", Path: p, Err: err}
	}

	return names, nil
}

// emptyIn removes everything in the directory s holds, p naming it, but keep, a name in it ("" for none),
// and is the paths of what it removed, however far it got: the directory opened again through s, to read
// (listing), and each name in it removed through that (removeAt), never followed.
func emptyIn(s step, p, keep string) ([]string, error) {
	fd, err := listing(s, p)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)

	names, err := namesIn(fd)
	if err != nil {
		return nil, &os.PathError{Op: "read", Path: p, Err: err}
	}

	var removed []string

	for _, name := range names {
		if keep != "" && name == keep {
			continue
		}

		switch err := removeAt(fd, name, filepath.Join(p, name)); {
		case errors.Is(err, unix.ENOENT):
		case err != nil:
			return removed, err
		default:
			removed = append(removed, filepath.Join(p, name))
		}
	}

	return removed, nil
}

// removeEmpty is RemoveWay's removal of name, an empty directory, in the directory parent is, which p
// names, by unlinkat, and whether it removed it: one holding anything, not there, or no longer a
// directory, a link among them, is left.
func removeEmpty(parent step, name, p string) (bool, error) {
	switch err := ignoringEINTR(func() error { return unix.Unlinkat(parent.fd, parent.at(name), unix.AT_REMOVEDIR) }); {
	case err == nil:
		return true, nil
	case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ENOTEMPTY), errors.Is(err, unix.EEXIST),
		errors.Is(err, unix.ENOTDIR):
		return false, nil
	default:
		return false, &os.PathError{Op: "remove", Path: p, Err: err}
	}
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

// secure refuses a root another account owns, or whose extended ACL lets another account write
// or move it, and narrows one of conflux's own that something left wider than 0700, or than the
// 0710 that lets anchord's account through. A CONFLUX_DIR's way is makeRoot's, which secure's one
// caller, EnsureAll, runs first, and so is the refusal of a directory others keep what is theirs in,
// or one conflux has not secured holding what conflux never makes there (sharedStep, strays), which
// makeRoot holds whatever
// is at the root's name to before secure narrows anything.
//
// makeRoot creates at 0700 and leaves a directory that already exists exactly as it
// found it, so without this an /etc/conflux somebody made at 0755 would hold the
// manifest in a traversable directory, and a CONFLUX_DIR another user made would hold
// the binary root runs at boot where that user can replace it. The owner decides, as on
// Windows: one that is not the account running conflux did not get its directory from
// conflux, and whatever it put there is not used. What a root holds is held to the
// same, before the root is narrowed and again after (contentsAs), as on Windows: whatever another
// account put in it while it was wider is refused, not adopted. Every refusal but the last comes
// before secure changes anything; a root that was not there EnsureAll has made by then, and a
// refusal leaves it, empty and this account's.
//
// installation is Windows's, where an installation's root is judged for the SYSTEM service; here the
// service runs as root, as every command that makes an installation's root does, so the two
// judgements are one.
func secure(dir string, _ bool) error { return secureAs(dir, os.Geteuid()) }

// secureAs is secure for a given effective uid, so the refusals can be tested without
// another account.
func secureAs(dir string, euid int) error {
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
	// of those, or there is none, it is not read (rootACLMayRefuse).
	if rootACLMayRefuse {
		writers, aclGroup, err := rootACL(dir, link)
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
	mode := fi.Mode().Perm()
	wide := mode != 0o700 && mode != 0o710

	// What the root holds, as found: a root wider than it is left let anybody put anything there,
	// which narrowing it takes nothing out of, a second name among it (secondNames).
	if err := contentsAs(dir, fi, euid, wide || secondNames(fi)); err != nil {
		return err
	}

	if !wide {
		return nil
	}

	if err := os.Chmod(dir, 0o700); err != nil {
		return fmt.Errorf("narrow %s to 0700: %w", dir, err)
	}

	narrowed(dir)

	// And again: whatever was put there before the narrowing, since it was judged, a second name
	// among it, which an account that could write the root while it was still wide may have made in
	// between. Nobody but root and this account can give a file in it one from now on.
	return contentsAs(dir, fi, euid, true)
}

// secondNames reports whether a file with a second name in a root fi says is as found -- not narrowed
// by secure -- is one only another account can have made there: in a root anchord's account cannot
// search, 0700, nobody but root and the account running conflux could, and conflux makes no file of
// two names, so a wide root narrowed by hand is held to it as one secure narrows is. In a 0710 root
// anchord's account, which may link what it can name, may have made one, and no refusal should send
// an operator to remove a file conflux keeps, the manifest among them: so a wide root narrowed by hand
// to 0710 keeps a second name another account made in it while it was wide, which only letting
// conflux narrow it would have refused (security.md).
func secondNames(fi os.FileInfo) bool { return fi.Mode().Perm() == 0o700 }

// narrowed is called once secure has narrowed a root, before it judges what the root holds again:
// nothing, but where a test adds to the root meanwhile.
var narrowed = func(string) {}

// ownedAs is what Lstat says of dir, and what dir resolves to, the same where it is not a link,
// once owns has held each to euid: secure's rule (ownedBy) or a reader's (readerOwns). A root that
// is a symlink is held to the same rule as what it points at: one another account planted would
// otherwise lead straight past the check into a directory of theirs, or of the system's. One that
// leads nowhere is refused as a link conflux cannot follow, never taken for a root not there.
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
		return nil, nil, fmt.Errorf("%s is a link conflux cannot follow, so conflux will not use it: %v.\n  Remove it, "+
			"then run this again", dir, err)
	}

	if err := owns(dir, fi, euid); err != nil {
		return nil, nil, err
	}

	return link, fi, nil
}

// ownedRoot refuses dir where secure would for its owner, or a link at its name's (ownedAs, ownedBy):
// any account's but this one's, root's among them for any other account.
func ownedRoot(dir string) error {
	_, _, err := ownedAs(dir, os.Geteuid(), ownedBy)

	return err
}

// checkRoot is Check's judgement of the root dir: checkRootAs for this process's effective uid.
func checkRoot(dir string) error {
	_, err := checkRootAs(dir, os.Geteuid())

	return err
}

// foreign is Foreign here, for this process's effective uid: the root held to checkRootAs, and what
// it holds to contentsAs, the root it opens held to the directory checkRootAs judged.
func foreign(dir string) error {
	euid := os.Geteuid()

	fi, err := checkRootAs(dir, euid)
	if err != nil {
		return err
	}

	checked(dir)

	return contentsAs(dir, fi, euid, secondNames(fi))
}

// checked is called once Foreign has held a root to the readers' check, before it judges what the
// root holds: nothing, but where a test replaces the root meanwhile.
var checked = func(string) {}

// contentsAs refuses the root dir, for euid, where anything in it another account could have put
// there, or may change, as Windows's contents does: a root left wider than conflux leaves one let
// anybody put what they liked in it -- a link for the service to write its log through as root, a
// configuration, a pid record -- and narrowing the root takes none of it out. Each entry is judged,
// as found, and each directory gone into, from the root held open (judgeIn): by what fstatat says of
// its name in the directory held, never followed, and its ACL read through a descriptor opened on it
// there, never by its name. A link is refused, whoever may change it: conflux makes none in a root.
// So is anything but a file, a directory or a socket; an entry another account owns, whatever its
// name; and anything another account may write -- a file's content, or a directory's names, which
// is how whoever may write it would retarget what it holds -- by its mode, the sticky bit letting
// nothing through, or its ACL (judge). Where seconds is true so is a file with a second name, a hard
// link another account may have made there to lead root's writes to wherever that is: in a root
// found wide -- one secure narrows, which may have let another account write it, judged before the
// narrowing and again after it -- and in one at 0700 (secondNames). In a 0710 root a second name is
// root's or this account's to have made, or anchord's account's, which may link what it can name and
// which no refusal should send an operator to remove, a manifest among it.
//
// anchord's own account (anchordAccount) is conflux's, as the account anchord runs as is on
// Windows: the supervisor gives it its -dir, anchor (made as anchor.new), its -config,
// anchord.json, written through a .tmp- file beside it, and its run directory, anchord in Run --
// run/anchord in a root that holds Run (anchordPlace). One of those that account owns is held to
// who else may write it, and a directory of them is not gone into: only root and anchord may make
// anything in it, and conflux reads what anchord makes there as anchord's, untrusted
// (OpenUntrusted, ReadUntrusted, copyTree). That account can make nothing elsewhere in a
// root, so what it owns anywhere else is refused as any other account's is.
//
// The root is opened by its name once, which secure and checkRootAs have just held, a link at it
// included, to its owner, and refused unless it is fi, the directory they judged (ownedAs).
func contentsAs(dir string, fi os.FileInfo, euid int, seconds bool) error {
	var fd int
	if err := ignoringEINTR(func() (err error) {
		fd, err = unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)

		return err
	}); err != nil {
		return &os.PathError{Op: "open", Path: dir, Err: err}
	}
	defer unix.Close(fd)

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return &os.PathError{Op: "stat", Path: dir, Err: err}
	}

	if was := fi.Sys().(*syscall.Stat_t); uint64(was.Dev) != uint64(st.Dev) || uint64(was.Ino) != uint64(st.Ino) {
		return fmt.Errorf("%s changed while conflux judged it, so conflux will not use it.\n  Run this again", dir)
	}

	return judgeIn(&judging{dir: dir, euid: euid, seconds: seconds, anchords: map[uint32]bool{}}, fd, "")
}

// judging is contentsAs's judgement of what the root dir holds, for euid: seconds is whether a file
// with a second name is refused there, and anchords keeps what anchordAccount said of each uid it was
// asked of.
type judging struct {
	dir      string
	euid     int
	seconds  bool
	anchords map[uint32]bool
}

// judgeIn is j's judgement of what is in the directory fd holds open, rel within the root.
func judgeIn(j *judging, fd int, rel string) error {
	names, err := namesIn(fd)
	if err != nil {
		return fmt.Errorf("read %s: %w", filepath.Join(j.dir, rel), err)
	}

	for _, name := range names {
		if err := judgeEntry(j, fd, filepath.Join(rel, name), name); err != nil {
			return err
		}
	}

	return nil
}

// judgeEntry is judgeIn's judgement of name, in the directory fd holds open, rel within the root,
// and, where it is a directory to go into, of what it holds. One gone since it was listed is passed
// over: nothing is there to judge, and a live run's root has its marker written and removed while
// it runs.
func judgeEntry(j *judging, fd int, rel, name string) error {
	dir, euid := j.dir, j.euid
	p := filepath.Join(dir, rel)

	var st unix.Stat_t

	switch err := ignoringEINTR(func() error { return unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW) }); {
	case errors.Is(err, unix.ENOENT):
		return nil
	case err != nil:
		return &os.PathError{Op: "stat", Path: p, Err: err}
	}

	kind := st.Mode & unix.S_IFMT

	switch kind {
	case unix.S_IFLNK:
		return fmt.Errorf("%s, a link, is in %s, where conflux makes none, so conflux will not use it.\n  Remove it, "+
			"then run this again", p, dir)
	case unix.S_IFDIR, unix.S_IFREG, unix.S_IFSOCK:
	default:
		return fmt.Errorf("%s, which is no file or directory conflux makes, is in %s, so conflux will not use it.\n  "+
			"Remove it, then run this again", p, dir)
	}

	theirs := st.Uid != 0 && int(st.Uid) != euid
	anchord := theirs && anchordPlace(rel) && anchordAccount(st.Uid, j.anchords)

	switch {
	case theirs && !anchord:
		return fmt.Errorf("%s, which belongs to uid %d, is in %s, so conflux did not make it and will not use it.\n  "+
			"Remove it, then run this again", p, st.Uid, dir)
	case j.seconds && kind == unix.S_IFREG && st.Nlink > 1:
		return fmt.Errorf("%s, which has another name, is in %s, where conflux makes no file of two names and no "+
			"account it trusts could have made one, so conflux will not use it: another account may have made "+
			"that name while the directory was wider than conflux leaves one.\n  Do not remove it before you "+
			"know what it is: find its other name (find / -xdev -samefile %s). A file of the system's means it was "+
			"put there for conflux to write to as root; a file of conflux's, the manifest among them, means "+
			"somebody gave it a second name. Run this again once it has one", p, dir, p)
	}

	// A socket is not opened -- anchord's is in a directory of its own -- and is held to its mode.
	var acl []writer

	aclGroup, sub := false, -1

	if kind != unix.S_IFSOCK {
		flags := unix.O_RDONLY | unix.O_NOFOLLOW | unix.O_NONBLOCK | unix.O_CLOEXEC
		if kind == unix.S_IFDIR {
			flags |= unix.O_DIRECTORY
		}

		var held unix.Stat_t

		err := ignoringEINTR(func() (err error) {
			sub, err = unix.Openat(fd, name, flags, 0)

			return err
		})
		if err == nil {
			defer unix.Close(sub)

			err = unix.Fstat(sub, &held)
		}

		switch {
		case err != nil:
			return &os.PathError{Op: "open", Path: p, Err: err}
		case held.Dev != st.Dev || held.Ino != st.Ino:
			return fmt.Errorf("%s changed while conflux judged it, so conflux will not use it.\n  Run this again", p)
		}

		if acl, aclGroup, err = aclOf(p, sub); err != nil {
			return err
		}
	}

	if who := judge(os.FileMode(st.Mode&0o777), st.Gid, acl, aclGroup, euid); who != "" {
		return fmt.Errorf("%s, which %s could change, is in %s, so conflux will not use it.\n  Remove it, then "+
			"run this again", p, who, dir)
	}

	if kind != unix.S_IFDIR || anchord {
		return nil
	}

	return judgeIn(j, sub, rel)
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

// anchordPlace reports whether rel, within a root, is where the supervisor gives anchord's own
// account what it needs (contentsAs).
func anchordPlace(rel string) bool {
	switch rel {
	case "anchor", "anchor.new", "anchord.json", "anchord", filepath.Join(runName, "anchord"):
		return true
	}

	return !strings.ContainsRune(rel, filepath.Separator) && strings.HasPrefix(rel, ".tmp-")
}

// anchordAccount reports whether uid is an account anchord runs as here, the installation's or an
// ephemeral run's (AccountName), as the account database names it; known keeps each answer.
func anchordAccount(uid uint32, known map[uint32]bool) bool {
	if is, ok := known[uid]; ok {
		return is
	}

	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	is := err == nil && (u.Username == AccountName("conflux") || u.Username == AccountName("conflux-ephemeral"))
	known[uid] = is

	return is
}

// checkRootAs refuses the root dir, for a command run as euid about to read what is in it by name,
// where another account could have put something there: one owned, or reached through a link
// owned, by an account other than root and euid (ownedAs, readerOwns), or whose mode or ACL, as
// found, lets another account write it (judge), the sticky bit letting nothing through, since a
// name not taken yet is anybody's in a sticky directory. A CONFLUX_DIR is held to its parents first
// (parentsAs). Nothing is narrowed, as secure would narrow it: a reader changes nothing. Where it
// passes, it is what dir resolves to, as ownedAs found it.
func checkRootAs(dir string, euid int) (os.FileInfo, error) {
	if chosen(dir) {
		if err := parentsAs(dir, euid); err != nil {
			return nil, err
		}
	}

	link, fi, err := ownedAs(dir, euid, readerOwns)
	if err != nil {
		return nil, err
	}

	writers, aclGroup, err := rootACL(dir, link)
	if err != nil {
		return nil, err
	}

	if who := judge(fi.Mode()&^os.ModeSticky, fi.Sys().(*syscall.Stat_t).Gid, writers, aclGroup, euid); who != "" {
		return nil, fmt.Errorf("%s is not conflux's alone: %s could put what it likes in it for conflux to read or "+
			"run, so conflux will not use it.\n  Let conflux narrow it, which judges what it holds as it does, rather "+
			"than narrowing it by hand: %s; an ephemeral run's narrows its own as it starts. Remove that entry from "+
			"its ACL first, if one lets another account write it; then run this again", dir, who, narrowing(dir))
	}

	return fi, nil
}

// narrowing is the way to let conflux narrow the root dir, as the readers' check advises it: for the
// machine's own, its start or install as root; for a CONFLUX_DIR's, the same start with CONFLUX_DIR
// handed on by name, since sudo, and doas, start a command with an environment of their own that keeps
// no CONFLUX_DIR, and would act on the machine's own; or up, where that installation has no service
// registered for start to start.
func narrowing(dir string) string {
	if !chosen(dir) {
		return "for the machine's own, run " + privcheck.Retry("conflux start") + " or " +
			privcheck.Retry("conflux install")
	}

	env := "env CONFLUX_DIR=" + shellWord(Root()) + " conflux "

	return "for this CONFLUX_DIR, run " + privcheck.Retry(env+"start") + ", or, where it has no service " +
		"registered, " + privcheck.Retry(env+"up")
}

// shellWord is s as one word a POSIX shell reads back as s: as it is where it holds nothing a shell
// treats specially, and otherwise in single quotes, a quote in it closed, escaped and opened again.
func shellWord(s string) string {
	plain := s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/._-+,:@%", r))
	}) < 0
	if plain {
		return s
	}

	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// readerOwns refuses dir, of which fi is what Lstat or Stat said, where it belongs to an account
// other than root and euid (notReaders).
func readerOwns(dir string, fi os.FileInfo, euid int) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("read the owner of %s: no ownership on this filesystem", dir)
	}

	return notReaders(dir, st.Uid, euid)
}

// notReaders refuses dir, owned by uid, where that is an account other than root and euid: one root's
// is root's to have made, and a reader trusts it as it trusts root.
func notReaders(dir string, uid uint32, euid int) error {
	if owner := int(uid); owner != 0 && owner != euid {
		return fmt.Errorf("%s belongs to uid %d, not to root or uid %d, which conflux runs as, so conflux did not "+
			"create it and will not use what is in it.\n  Remove it, then run this again", dir, owner, euid)
	}

	return nil
}

// rootOwner refuses the root dir, the directory s holds, where an account other than root and the one
// running conflux owns it (notReaders), as fstat read it where the walk met it.
func rootOwner(dir string, s step) error { return notReaders(dir, s.st.Uid, os.Geteuid()) }

// heldLinkRule refuses dir, the link s holds by its name, where an account other than root and the one
// running conflux owns it (notReaders), who could point it at a directory of their own -- a link's mode
// means nothing, and whoever may write the directory it is in is judged with the way to it -- as the
// readers' check and secure hold a link at a root's name (ownedAs).
func heldLinkRule(dir string, s step) (linkSecurity, error) {
	if err := notReaders(dir, s.st.Uid, os.Geteuid()); err != nil {
		return linkSecurity{}, fmt.Errorf("%s is a link whose owner could point it at a directory of their own, so "+
			"conflux will not follow it: %w", dir, err)
	}

	return linkSecurity{}, nil
}

// linkSecurity is what holdRoot keeps of a link at a root's name for a judgement after follow's:
// nothing here, where its owner is all heldLinkRule judges.
type linkSecurity struct{}

// serviceFollows reports whether the boot service would follow the link at a root's name that follow
// has: it would, since it runs as root, as every command that makes, remakes or removes an
// installation's root does, so follow's judgement, for this account, is the service's.
func serviceFollows(string, linkSecurity) bool { return true }

// ledRoot refuses the directory the link at the root dir's name leads to, which s holds and p names,
// where an account other than root and the one running conflux owns it (notReaders), as fstat read it
// where the walk met it: the owner a root at the name itself is held to (rootOwner). A directory of
// conflux's own left wider than conflux leaves one is EnsureAll's to narrow, judging what it holds as
// found, as a root at the name itself is.
func ledRoot(dir, p string, s step) error {
	if err := notReaders(p, s.st.Uid, os.Geteuid()); err != nil {
		return fmt.Errorf("%s is a link to a directory conflux will not use: %w", dir, err)
	}

	return nil
}

// fileID is a file as the system knows it, whatever name leads to it: its device and inode.
type fileID struct{ dev, ino uint64 }

// idOf is the file p leads to, or false where it cannot be read.
func idOf(p string) (fileID, bool) {
	statting(p)

	var st unix.Stat_t
	if err := unix.Stat(p, &st); err != nil {
		return fileID{}, false
	}

	return fileID{uint64(st.Dev), uint64(st.Ino)}, true
}

// statting is called with each path idOf reads: nothing, but where a test counts them.
var statting = func(string) {}

// systemPlaces are the directories no root of conflux's may be, by the file each is, and why
// (systemPlacesOf); the filesystem's root, by its path and the file it is (slash), which a directory
// directly under it is judged by; and the directory the running conflux is in, held apart (exeDir), with
// the running conflux itself (exe).
type systemPlaces struct {
	dirs      map[fileID]string
	slashPath string
	slash     fileID
	exeDir    fileID
	exe       fileID
}

// systemDirs are this process's systemPlaces, read once: the running conflux, the platform's places
// and the system's log directory do not move while it runs.
var systemDirs = sync.OnceValue(func() systemPlaces {
	exe, err := os.Executable()
	if err != nil {
		exe = ""
	}

	return systemPlacesOf("/", exe, platformDirs())
})

// systemPlacesOf is the systemPlaces of a process running exe on a platform whose roots are kept in
// platform by default, whose filesystem's root is slash: that root; each directory above one of the
// platform's roots, which are the system's; the system's log directory (sharedLog); and each directory
// above the one exe is in, which is held apart, since it is the root the boot service runs its copy of
// conflux from. Nothing else in slash is read: whether a root is directly under it is asked of that root
// alone, as it is judged (sharedRootIn), since reading what slash holds would stat a mount whose server
// is gone, and wait on it, in every process that makes a root.
func systemPlacesOf(slash, exe string, platform Dirs) systemPlaces {
	ps := systemPlaces{dirs: map[fileID]string{}, slashPath: slash}

	add := func(p, why string) {
		if id, ok := idOf(p); ok {
			if _, had := ps.dirs[id]; !had {
				ps.dirs[id] = why
			}
		}
	}

	above := func(p, why string) {
		for a := filepath.Dir(p); ; a = filepath.Dir(a) {
			add(a, why)

			if a == filepath.Dir(a) {
				return
			}
		}
	}

	ps.slash, _ = idOf(slash)

	add(slash, "the filesystem's root")
	add(sharedLog, "the system's log directory")

	for _, root := range []string{platform.Config, platform.State, platform.Run, platform.Log} {
		if root != "" {
			above(root, "a directory of the system's, above where conflux keeps a root by default")
		}
	}

	if exe != "" {
		ps.exeDir, _ = idOf(filepath.Dir(exe))
		ps.exe, _ = idOf(exe)
		above(filepath.Dir(exe), "above the directory the running conflux is in")
	}

	return ps
}

// sharedRootIn refuses the root dir, the directory s holds, as fstat read it where the walk met it,
// where it is a directory others keep what is theirs in, which conflux never narrows, fills or
// empties, whoever owns it: a sticky one -- /tmp, /var/tmp, /dev/shm -- or one ps names: the
// filesystem's root, a directory of the system's above where a platform root is kept by default, the
// system's log directory, or one above the directory the running conflux is in. A directory directly
// under the filesystem's root is the system's too, but where it is a root conflux made: owned by root
// or the account running conflux (notReaders), at 0700 or 0710, as conflux secures a root, and
// holding something -- every root conflux made holds its run directory, or more -- which strays then
// holds to conflux's names. The directory the running conflux is in is refused too. The boot service's
// own root is the one exception to both: where the running conflux is the copy the service runs there
// (serviceCopy) and the root already holds this installation's own state (stateIn), it is taken whatever
// its mode, and secure narrows it where it finds it widened, rather than refuse it at every start. A
// folder holding the running conflux and nothing of the installation's -- /usr/local/bin, where conflux
// was installed -- is refused, the copy's name there or not; and a sticky one is refused whatever it holds.
func sharedRootIn(ps systemPlaces, dir string, s step) error {
	id := fileID{uint64(s.st.Dev), uint64(s.st.Ino)}
	why := ps.dirs[id]

	service := why == "" && id == ps.exeDir && serviceCopy(ps, s) && stateIn(dir, s)

	switch {
	case s.st.Mode&unix.S_ISVTX != 0:
		why = "a sticky directory, which every account shares"
	case service:
	case why == "" && id == ps.exeDir:
		why = "the directory the running conflux is in"
	case why == "" && ps.top(dir, s) && !madeTop(dir, s):
		why = "a directory of the system's, directly under the filesystem's root, which conflux did not make a root"
	}

	if why == "" {
		return nil
	}

	way := "Point it at a directory of its own, then run this again"
	if !chosen(dir) {
		way = "It is no directory conflux made: remove it, then run this again"
	}

	return fmt.Errorf("%s is %s, so conflux will not use it as a root: it never narrows, fills or empties a "+
		"directory others keep what is theirs in.\n  %s", dir, why, way)
}

// top reports whether the root dir, the directory s holds, is directly under the filesystem's root:
// its name is, or the directory it is, whose "..", as fstatat says of it through s, is that root. Where
// that cannot be read it is taken to be, so that a refusal answers for what cannot be told.
func (ps systemPlaces) top(dir string, s step) bool {
	if filepath.Dir(dir) == ps.slashPath {
		return true
	}

	var st unix.Stat_t
	if err := ignoringEINTR(func() error {
		return unix.Fstatat(s.fd, s.at(".."), &st, unix.AT_SYMLINK_NOFOLLOW)
	}); err != nil {
		return true
	}

	return (fileID{uint64(st.Dev), uint64(st.Ino)}) == ps.slash
}

// serviceCopy reports whether the running conflux, ps.exe, is the copy the boot service runs from the
// root s holds (ServiceExecutable): the file at that copy's name there, as fstatat says of it, never
// followed, one file with the running conflux -- which, being run, is a regular file, so a link or
// anything else at the name is never it.
func serviceCopy(ps systemPlaces, s step) bool {
	var st unix.Stat_t
	if err := ignoringEINTR(func() error {
		return unix.Fstatat(s.fd, s.at(filepath.Base(Dirs{}.ServiceExecutable())), &st, unix.AT_SYMLINK_NOFOLLOW)
	}); err != nil {
		return false
	}

	return (fileID{uint64(st.Dev), uint64(st.Ino)}) == ps.exe
}

// madeTop reports whether dir, a directory directly under the filesystem's root that s holds, is one
// conflux made a root of (sharedRootIn): root's or the account running conflux's, at 0700 or 0710, and
// holding something.
func madeTop(dir string, s step) bool {
	if perm := s.st.Mode & 0o7777; notReaders(dir, s.st.Uid, os.Geteuid()) != nil || perm != 0o700 && perm != 0o710 {
		return false
	}

	names, err := namesOf(s, dir)

	return err == nil && len(names) > 0
}

// sharedStep refuses the root dir, the directory s holds, where it is one others keep what is theirs in
// (sharedRootIn), as fstat read it where the walk met it.
func sharedStep(dir string, s step) error { return sharedRootIn(systemDirs(), dir, s) }

// securedStep refuses the directory s holds, which p names -- the root dir itself, or where a link at
// its name leads -- where conflux has not secured it as a root, as it secures every root it uses at its
// first start: owned by root or the account running conflux, at 0700 or the 0710 that lets anchord's
// account through, and no ACL letting another account write it (judge), as fstat read it where the walk
// met it and its ACL at p, which leads through no link.
func securedStep(dir, p string, s step) error {
	euid := os.Geteuid()

	who := ""
	if owner := int(s.st.Uid); owner != 0 && owner != euid {
		who = fmt.Sprintf("uid %d, which owns it,", owner)
	}

	if who == "" {
		acl, aclGroup, err := aclOf(p, -1)
		if err != nil {
			return err
		}

		mode := os.FileMode(s.st.Mode & 0o7777)

		who = judge(mode&0o777, s.st.Gid, acl, aclGroup, euid)
		if who == "" && mode != 0o700 && mode != 0o710 {
			who = fmt.Sprintf("its mode, %#o, not one conflux leaves a root at, says nothing secured it; and whoever "+
				"made it", uint32(mode))
		}
	}

	if who != "" {
		return unsecuredRefusal(dir, p, who)
	}

	return nil
}

// sameStep reports whether a and b are one directory, as fstat read them where the walk met each.
func sameStep(a, b step) bool { return a.st.Dev == b.st.Dev && a.st.Ino == b.st.Ino }

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

	acl, aclGroup, err := aclOf(p, -1)
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

// rootACL is who the ACL of the root dir lets write it, and whether that ACL says what its group may
// (aclOf), link being what Lstat said of dir: read where dir leads, since a link's own ACL says
// nothing.
func rootACL(dir string, link os.FileInfo) ([]writer, bool, error) {
	acl := dir
	if isLink(link) {
		var err error
		if acl, err = filepath.EvalSymlinks(dir); err != nil {
			return nil, false, fmt.Errorf("read %s: %w", dir, err)
		}
	}

	return aclOf(acl, -1)
}

// aclOf is who p's ACL lets write it, and whether that ACL says what p's group may
// (extendedWriters), for judge, or judgeRoot, to hold beside p's mode: read through fd where it is
// open on p, else at p; a failure names p.
func aclOf(p string, fd int) ([]writer, bool, error) {
	acl, aclGroup, err := extendedWriters(p, fd)
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
