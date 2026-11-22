//go:build !windows

package paths

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// Restrict is Windows's. Here a mode set on the descriptor and a 0700 directory that belongs to
// whoever runs conflux are the whole of it, and EnsureAll is what makes sure of the second.

// Restrict is a no-op here.
func Restrict(string, bool) error { return nil }

// RestrictToOwner is a no-op here: the mode set on the descriptor is the restriction.
func RestrictToOwner(string, bool) error { return nil }

// ours is why what s holds -- a directory, at the root dir's name or a folder's in one, or a file in one --
// is not as conflux makes it, or "" where it is: owned by root or the account running conflux, and written
// by nobody else by its mode -- the sticky bit letting nothing through, since a name not taken yet is
// anybody's in a sticky directory -- as fstat read it where the walk met it. That is the whole of it: a
// root's location is fixed, in a folder only root may write, so no ACL is read. A 0710 the supervisor gives
// the state and run directories, so that anchord's account may pass through them, lets that account write
// nothing.
func ours(_ string, s step) (string, error) {
	if owner := int(s.st.Uid); owner != 0 && owner != os.Geteuid() {
		return fmt.Sprintf("uid %d owns it", owner), nil
	}

	switch {
	case s.st.Mode&0o002 != 0:
		return "anybody may write, and anybody could put what they like in it", nil
	case s.st.Mode&0o020 != 0:
		return fmt.Sprintf("its group, gid %d, may write, and any account in it could put what they like in it",
			s.st.Gid), nil
	}

	return "", nil
}

// ElevatedDefaultOwner is a no-op here: what conflux makes is the account's that makes it, root's
// for an installation's root, which every command making it runs as.
func ElevatedDefaultOwner() error { return nil }

// aLink is what ownFolder calls a link made where it was making a directory.
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
// as errNotDir, and nothing at it is an error that is fs.ErrNotExist. What fstatat reads of the name,
// once the open has refused it, is what is there by then: the lookup by name any program makes there.
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

// lookAt is what is at name in the directory parent is, and its kind: by its name there, never followed,
// with what fstatat reads of it. Nothing at the name is an error that is fs.ErrNotExist.
func lookAt(parent step, name string) (step, kind, error) {
	s := step{fd: parent.fd, rel: parent.at(name)}
	if err := ignoringEINTR(func() error {
		return unix.Fstatat(parent.fd, s.rel, &s.st, unix.AT_SYMLINK_NOFOLLOW)
	}); err != nil {
		return step{}, isOther, err
	}

	switch s.st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		return s, isFile, nil
	case unix.S_IFDIR:
		return s, isFolder, nil
	case unix.S_IFLNK:
		return s, isLink, nil
	}

	return s, isOther, nil
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
// ownFolder goes into it as a walk would (lookUp).
func makeStep(parent step, name string) (step, bool, error) {
	return step{}, false, ignoringEINTR(func() error { return unix.Mkdirat(parent.fd, parent.at(name), 0o700) })
}

// removeFrom is RemoveRoot's, ownFile's and ownFolder's removal of name, in the directory parent is,
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
