//go:build !windows

package paths

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func mode(t *testing.T, dir string) os.FileMode {
	t.Helper()

	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}

	return fi.Mode().Perm()
}

// TestEnsureAllNarrowsAnOpenRoot: a root of conflux's own that something left at 0755 holds
// the manifest in a directory anybody can traverse, so it is narrowed, not adopted as found.
func TestEnsureAllNarrowsAnOpenRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONFLUX_DIR", root)

	if err := Default().EnsureAll(); err != nil {
		t.Fatal(err)
	}

	if got := mode(t, root); got != 0o700 {
		t.Errorf("the root is %#o after EnsureAll, want 0700", got)
	}
}

// TestSecureRefusesARootAnotherAccountOwns: whatever another account put in a directory
// it made is not used, and the directory is left exactly as it was found.
func TestSecureRefusesARootAnotherAccountOwns(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	err := secureAs(dir, os.Geteuid()+1)
	if err == nil {
		t.Fatal("a root owned by another uid was accepted")
	}

	if !strings.Contains(err.Error(), "belongs to") {
		t.Errorf("the refusal does not say why: %v", err)
	}

	if got := mode(t, dir); got != 0o755 {
		t.Errorf("the refused root was changed to %#o; a refusal must change nothing", got)
	}
}

// TestSecureNamesRootWhenRootOwnsIt: the common way to meet a root-owned root is to have
// forgotten sudo, so that is what the refusal says. Safe as any user: it refuses first.
func TestSecureNamesRootWhenRootOwnsIt(t *testing.T) {
	err := secureAs("/", 1000)
	if err == nil || !strings.Contains(err.Error(), "belongs to root") {
		t.Fatalf("secureAs(\"/\", 1000) = %v, want a refusal naming root", err)
	}
}

// TestSecureFollowsASymlinkOnlyToItsOwnersDirectory: a root that is a link is held to the
// owner of the link and of what it points at.
func TestSecureFollowsASymlinkOnlyToItsOwnersDirectory(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "root")

	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(target, 0o750); err != nil {
		t.Fatal(err)
	}

	if err := secure(link); err != nil {
		t.Fatalf("a link to a directory of our own was refused: %v", err)
	}

	if got := mode(t, target); got != 0o700 {
		t.Errorf("the link's target is %#o, want 0700", got)
	}

	if err := secureAs(link, os.Geteuid()+1); err == nil {
		t.Error("a link another uid owns was accepted")
	}

	// A link of our own that leads into a directory of somebody else's is held to theirs.
	theirs := "/" // root's, for anybody else to point a link at
	if os.Geteuid() == 0 {
		// Root can make one that belongs to somebody else.
		theirs = filepath.Join(t.TempDir(), "theirs")
		if err := os.Mkdir(theirs, 0o700); err != nil {
			t.Fatal(err)
		}

		if err := os.Chown(theirs, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}

	before := mode(t, theirs)

	into := filepath.Join(t.TempDir(), "root")
	if err := os.Symlink(theirs, into); err != nil {
		t.Fatal(err)
	}

	if err := secure(into); err == nil || !strings.Contains(err.Error(), "belongs to") {
		t.Errorf("a link of ours into a directory another account owns was not refused for its owner: %v", err)
	}

	if got := mode(t, theirs); got != before {
		t.Errorf("the directory the refused link leads to was changed to %#o", got)
	}
}

// TestEnsureAllLeavesTheSharedLogAlone: macOS and FreeBSD write the service's log into the
// system's /var/log, which is not conflux's to narrow.
func TestEnsureAllLeavesTheSharedLogAlone(t *testing.T) {
	shared := t.TempDir()
	if err := os.Chmod(shared, 0o755); err != nil {
		t.Fatal(err)
	}

	defer func(was string) { sharedLog = was }(sharedLog)
	sharedLog = shared

	root := t.TempDir()
	d := Dirs{Config: root, State: root, Run: filepath.Join(root, "run"), Log: shared}

	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	if got := mode(t, shared); got != 0o755 {
		t.Errorf("the shared log directory became %#o; conflux must leave it as the system made it", got)
	}
}

// TestSecureKeepsThePassThroughGroup: a root of ours at 0710 is how the supervisor lets
// anchord's own account pass through to what it runs, and every conflux command would
// otherwise cut a running anchord off; anything wider is still narrowed.
func TestSecureKeepsThePassThroughGroup(t *testing.T) {
	dir := t.TempDir()

	if err := os.Chmod(dir, 0o710); err != nil {
		t.Fatal(err)
	}

	if err := secure(dir); err != nil {
		t.Fatal(err)
	}

	if got := mode(t, dir); got != 0o710 {
		t.Errorf("0710 was changed to %#o", got)
	}

	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}

	if err := secure(dir); err != nil {
		t.Fatal(err)
	}

	if got := mode(t, dir); got != 0o700 {
		t.Errorf("0750 is %#o after secure, want 0700", got)
	}
}

// TestEnsureAllRefusesARootAnotherAccountCanMove: whoever may write a directory above a
// CONFLUX_DIR can move the root aside and put a directory of their own in its place, with
// a conflux in it for the boot service to run as root. So a root under one is refused,
// naming the directory and who may write it, before anything is changed -- unless it is
// sticky, as /tmp is, where nobody may move what is not theirs.
func TestEnsureAllRefusesARootAnotherAccountCanMove(t *testing.T) {
	for _, c := range []struct {
		name string
		mode os.FileMode
		who  string
	}{
		{"anybody may write it", 0o777, "anybody"},
		{"its group, with another account in it, may write it", 0o770, "its group"},
	} {
		t.Run(c.name, func(t *testing.T) {
			defer func(was func(string, string) ([]string, error)) { groupUsers = was }(groupUsers)
			groupUsers = func(string, string) ([]string, error) { return []string{"mallory"}, nil }

			parent := t.TempDir()
			root := filepath.Join(parent, "conflux")

			if err := os.Mkdir(root, 0o755); err != nil {
				t.Fatal(err)
			}

			if err := os.Chmod(root, 0o755); err != nil {
				t.Fatal(err)
			}

			if err := os.Chmod(parent, c.mode); err != nil {
				t.Fatal(err)
			}

			t.Setenv("CONFLUX_DIR", root)

			err := Default().EnsureAll()
			if err == nil {
				t.Fatalf("a root in %s, which %s may write, was accepted", parent, c.who)
			}

			if !strings.Contains(err.Error(), parent) || !strings.Contains(err.Error(), c.who) {
				t.Errorf("the refusal does not name %s and who may write it: %v", parent, err)
			}

			if got := mode(t, root); got != 0o755 {
				t.Errorf("the refused root was changed to %#o; a refusal must change nothing", got)
			}
		})
	}

	// A parent that belongs to another account is that account's to open up whenever it
	// likes, whatever its mode says now.
	t.Run("another account owns it", func(t *testing.T) {
		root := foundRoot(t)

		err := parentsAs(root, os.Geteuid()+1)
		if err == nil || !strings.Contains(err.Error(), "belongs to uid") {
			t.Errorf("a root in a directory another uid owns was accepted, or the refusal does not say why: %v", err)
		}
	})

	// A root that is a link is held to the directories above where it leads, too.
	t.Run("a link into one", func(t *testing.T) {
		target := foundRoot(t)
		open := filepath.Dir(target)

		if err := os.Chmod(open, 0o777); err != nil {
			t.Fatal(err)
		}

		safe := t.TempDir()
		if err := os.Chmod(safe, 0o700); err != nil {
			t.Fatal(err)
		}

		link := filepath.Join(safe, "conflux")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}

		t.Setenv("CONFLUX_DIR", link)

		if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), open) {
			t.Errorf("a link into a directory anybody may write was accepted, or the refusal does not name it: %v", err)
		}
	})

	// And to the directory every link on the way is in, where the chain ends somewhere safe:
	// whoever may write one can point its link anywhere.
	t.Run("a chain of links through one", func(t *testing.T) {
		a, open, safe := t.TempDir(), t.TempDir(), t.TempDir()
		for _, dir := range []string{a, safe} {
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}

		real := filepath.Join(safe, "real")
		if err := os.Mkdir(real, 0o700); err != nil {
			t.Fatal(err)
		}

		l2 := filepath.Join(open, "l2")
		if err := os.Symlink(real, l2); err != nil {
			t.Fatal(err)
		}

		if err := os.Chmod(open, 0o777); err != nil {
			t.Fatal(err)
		}

		l1 := filepath.Join(a, "l1")
		if err := os.Symlink(l2, l1); err != nil {
			t.Fatal(err)
		}

		t.Setenv("CONFLUX_DIR", l1)

		if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), open) {
			t.Errorf("a root reached through a link in a directory anybody may write was accepted, or the refusal does not name it: %v", err)
		}
	})

	// A link on the way that belongs to another account is that account's to point elsewhere,
	// even in a sticky directory, where nobody else may rename it. /tmp is root's and sticky,
	// and the link leads to /, so only the link is another account's: this one's, held to
	// another uid -- or, for root, a link given to another account.
	t.Run("a link another account owns", func(t *testing.T) {
		tmp, err := filepath.EvalSymlinks("/tmp") // /private/tmp on macOS
		if err != nil {
			t.Fatal(err)
		}

		link := filepath.Join(tmp, "conflux-link-"+strconv.FormatInt(time.Now().UnixNano(), 36))
		if err := os.Symlink("/", link); err != nil {
			t.Fatal(err)
		}

		t.Cleanup(func() { os.Remove(link) })

		euid := os.Geteuid() + 1
		if os.Geteuid() == 0 {
			euid = 0
			if err := os.Lchown(link, 65534, 65534); err != nil {
				t.Fatal(err)
			}
		}

		err = parentsAs(filepath.Join(link, "tmp"), euid)
		if err == nil || !strings.Contains(err.Error(), "reached through "+link) {
			t.Errorf("a root reached through a link another uid owns was accepted, or the refusal does not name it: %v", err)
		}
	})

	t.Run("sticky", func(t *testing.T) {
		parent := t.TempDir()
		if err := os.Chmod(parent, 0o777|os.ModeSticky); err != nil {
			t.Fatal(err)
		}

		t.Setenv("CONFLUX_DIR", filepath.Join(parent, "conflux"))

		if err := Default().EnsureAll(); err != nil {
			t.Errorf("a root in a sticky directory was refused: %v", err)
		}
	})
}

// TestEnsureAllTakesAGroupOfItsOwn: a parent its group may write lets no other account write
// it when the group lets in nobody but the account conflux runs as -- Ubuntu's group of one
// user, under its umask of 002 -- so a CONFLUX_DIR under it is accepted. One that lets
// anybody else in, or that the group database cannot answer for, is still refused.
func TestEnsureAllTakesAGroupOfItsOwn(t *testing.T) {
	me, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name    string
		users   []string
		err     error
		refused string
	}{
		{name: "this account alone", users: []string{me.Username}},
		{name: "nobody", users: nil},
		{name: "this account and another", users: []string{me.Username, "mallory"}, refused: "its group"},
		{name: "an answer the database cannot give", err: errors.New("getent group: exit status 2"), refused: "its group"},
	} {
		t.Run(c.name, func(t *testing.T) {
			groupWritableParent(t, func(bool) ([]string, error) { return c.users, c.err })

			ensureAllRefuses(t, fmt.Sprintf("a root its group may write, the group letting in %q,", c.users), c.refused)
		})
	}
}

// groupWritableParent is a fresh directory its group may write, 0770, with CONFLUX_DIR set to
// conflux inside it, not made yet, and groupUsers answering for any group, until the test
// ends, with whom users names, own saying whether it is the directory's own.
func groupWritableParent(t *testing.T, users func(own bool) ([]string, error)) string {
	t.Helper()

	parent := t.TempDir()
	if err := os.Chmod(parent, 0o770); err != nil {
		t.Fatal(err)
	}

	fi, err := os.Stat(parent)
	if err != nil {
		t.Fatal(err)
	}

	own := strconv.FormatUint(uint64(fi.Sys().(*syscall.Stat_t).Gid), 10)

	was := groupUsers
	t.Cleanup(func() { groupUsers = was })
	groupUsers = func(_, gid string) ([]string, error) { return users(gid == own) }

	t.Setenv("CONFLUX_DIR", filepath.Join(parent, "conflux"))

	return parent
}

// ensureAllRefuses is EnsureAll's answer held to refused: a refusal whose words hold it, or none
// where it is "". root is the root as a failure describes it.
func ensureAllRefuses(t *testing.T, root, refused string) {
	t.Helper()

	switch err := Default().EnsureAll(); {
	case refused != "" && (err == nil || !strings.Contains(err.Error(), refused)):
		t.Errorf("%s was accepted, or not for %s: %v", root, refused, err)
	case refused == "" && err != nil:
		t.Errorf("%s was refused: %v", root, err)
	}
}

// TestAncestorsFollowsEveryLink: the lookup is followed as the kernel makes it, a link's
// target read from the directory the link is in, ".." included, and each directory a name is
// looked up in is there once, the links with them, and not the directory the root resolves to.
// What the lookup read of each name it looked up goes with it, a link read as one, and only the
// top of the volume, which it looked no name up for, goes without: a directory ".." leads back to
// keeps what was read of it on the way down.
func TestAncestorsFollowsEveryLink(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir()) // under /private/var on macOS
	if err != nil {
		t.Fatal(err)
	}

	for _, dir := range []string{"a", "b/c", "d"} {
		if err := os.MkdirAll(filepath.Join(base, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	// a/l -> ../d/m, and d/m -> <base>/b/c, absolute: the root is b/c, reached through d.
	if err := os.Symlink("../d/m", filepath.Join(base, "a", "l")); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(filepath.Join(base, "b", "c"), filepath.Join(base, "d", "m")); err != nil {
		t.Fatal(err)
	}

	steps, err := ancestors(filepath.Join(base, "a", "l"))
	if err != nil {
		t.Fatal(err)
	}

	var got []string

	for _, s := range steps {
		got = append(got, s.path)

		link := s.path == filepath.Join(base, "a", "l") || s.path == filepath.Join(base, "d", "m")
		if s.fi != nil && (s.fi.Name() != filepath.Base(s.path) || isLink(s.fi) != link) || s.fi == nil && s.path != "/" {
			t.Errorf("ancestors read %s as %v", s.path, s.fi)
		}
	}

	for _, want := range []string{"/", base, filepath.Join(base, "a"), filepath.Join(base, "a", "l"),
		filepath.Join(base, "d"), filepath.Join(base, "d", "m"), filepath.Join(base, "b")} {
		if !slices.Contains(got, want) {
			t.Errorf("ancestors lacks %s: %q", want, got)
		}
	}

	for i, p := range got {
		if p == filepath.Join(base, "b", "c") || slices.Contains(got[:i], p) {
			t.Errorf("ancestors holds %s, which is the root or met already: %q", p, got)
		}
	}

	// a/up -> ../d: the lookup goes back up to base, and no later link meets it again.
	if err := os.Symlink("../d", filepath.Join(base, "a", "up")); err != nil {
		t.Fatal(err)
	}

	if steps, err = ancestors(filepath.Join(base, "a", "up")); err != nil {
		t.Fatal(err)
	}

	for _, s := range steps {
		if s.fi == nil && s.path != "/" {
			t.Errorf("ancestors read %s, which \"..\" led back to, as nothing", s.path)
		}
	}
}

// TestJudgeHoldsAnACLToTheStickyBit: a sticky directory lets nobody rename what is not theirs,
// so an ACL entry that only lets somebody write it is let through there, as its mode's bits
// are -- ZFS's trivial ACL for a 1777 /tmp among them -- but not one that lets them delete what
// is in it, delete it, or change its ACL or owner, which the sticky bit does not hold back.
// Nowhere is a deny entry, or the everyone-deny-delete on a macOS home directory, read as
// anything.
func TestJudgeHoldsAnACLToTheStickyBit(t *testing.T) {
	const allow, deny = nfs4Allow, 0x0200

	tmp, err := freebsdACL(freebsdBuf(
		[5]uint32{0x01, 0, 0x1ffff, allow},
		[5]uint32{0x40, 0, nfs4AddFile | nfs4AddSubdirectory, allow}), true)
	if err != nil {
		t.Fatal(err)
	}

	deletes, err := kauthAttr(kauthAttrBuf(kauthEntry{kauthEveryone, kauthPermit, kauthDeleteChild}))
	if err != nil {
		t.Fatal(err)
	}

	moves, err := freebsdACL(freebsdBuf(
		[5]uint32{0x01, 0, 0x1ffff, allow},
		[5]uint32{0x02, 1002, nfs4Delete, allow}), true)
	if err != nil {
		t.Fatal(err)
	}

	home, err := kauthAttr(kauthAttrBuf(kauthEntry{kauthEveryone, deny, kauthDelete}))
	if err != nil {
		t.Fatal(err)
	}

	sticky := os.ModeDir | os.ModeSticky | 0o777
	euid := os.Geteuid()

	for _, c := range []struct {
		name    string
		mode    os.FileMode
		acl     []writer
		refused string
	}{
		{"a sticky /tmp's trivial NFSv4 ACL", sticky, tmp, ""},
		{"the same ACL without the sticky bit", sticky &^ os.ModeSticky, tmp, "anybody"},
		{"a sticky directory everybody may delete from", sticky, deletes, "anybody"},
		{"a sticky directory another account may delete", sticky, moves, "uid 1002"},
		{"a home directory's deny", os.ModeDir | 0o750, home, ""},
		{"a UUID's write", os.ModeDir | 0o755, []writer{{who: anAccount, uuid: "5B1E0F1C-2D3E-4F50-6172-8394A5B6C7D8"}},
			"5B1E0F1C-2D3E-4F50-6172-8394A5B6C7D8"},
		{"root's write", os.ModeDir | 0o755, []writer{{who: aUser, id: 0}}, ""},
	} {
		got := judge(c.mode, 0, c.acl, false, euid)

		switch {
		case c.refused != "" && !strings.Contains(got, c.refused):
			t.Errorf("%s: judge = %q, want a refusal naming %s", c.name, got, c.refused)
		case c.refused == "" && got != "":
			t.Errorf("%s: judge = %q, want nothing", c.name, got)
		}
	}
}

// TestJudgeHoldsARootAsSecureLeavesIt: secure judges a root's own ACL by the mode it finds the
// root at (judgeRoot), as the root will be once narrowed, 0700 with no sticky bit. An extended ACL
// keeps its entries through that, so one letting anybody add a file to a root found at 0755,
// whose mode shows no such write, or at 01755, whose sticky bit the narrowing takes away, or an
// account named by its UUID add a directory to one found at 0777, is refused; a POSIX ACL's mask
// becomes the narrowed group bits, so its entries let nobody write, though one lets uid 65534 at
// the 0770 the root is found at.
func TestJudgeHoldsARootAsSecureLeavesIt(t *testing.T) {
	nfs4, err := freebsdACL(freebsdBuf(
		[5]uint32{0x01, 0, 0x1ffff, nfs4Allow},
		[5]uint32{0x40, 0, nfs4AddFile, nfs4Allow}), true)
	if err != nil {
		t.Fatal(err)
	}

	someone := [16]byte{0x5b, 0x1e, 0x0f, 0x1c, 0x2d, 0x3e, 0x4f, 0x50, 0x61, 0x72, 0x83, 0x94, 0xa5, 0xb6, 0xc7, 0xd8}

	kauth, err := kauthAttr(kauthAttrBuf(kauthEntry{someone, kauthPermit, kauthAppendData}))
	if err != nil {
		t.Fatal(err)
	}

	entries, err := linuxACL(anotherMayWrite)
	if err != nil {
		t.Fatal(err)
	}

	posix := posixWriters(entries)

	for _, c := range []struct {
		name     string
		mode     os.FileMode
		acl      []writer
		aclGroup bool
		refused  string
	}{
		{"an NFSv4 entry letting anybody add a file, found at 0755", 0o755, nfs4, false, "anybody"},
		{"the NFSv4 entry, found sticky at 01755", os.ModeSticky | 0o755, nfs4, false, "anybody"},
		{"a macOS entry letting an account add a directory, found at 0777", 0o777, kauth, false,
			"5B1E0F1C-2D3E-4F50-6172-8394A5B6C7D8"},
		{"a POSIX entry letting uid 65534 write, found at 0770", 0o770, posix, true, ""},
	} {
		got := judgeRoot(os.ModeDir|c.mode, 0, c.acl, c.aclGroup, os.Geteuid())

		switch {
		case c.refused != "" && !strings.Contains(got, c.refused):
			t.Errorf("%s: judgeRoot = %q, want a refusal naming %s", c.name, got, c.refused)
		case c.refused == "" && got != "":
			t.Errorf("%s: judgeRoot = %q, want nothing", c.name, got)
		}
	}
}

// TestJudgeLeavesARootsTrivialNFSv4ACLToTheNarrowing: an NFSv4 ACL keeps the mode in its owner@,
// group@ and everyone@ entries -- ZFS's trivial ACL, and UFS's with nfsv4acls -- which chmod
// rewrites with the mode. So a root found at 0775, or 0777, whose ACL is that and nothing else is
// the narrowing's, as a POSIX ACL is: accepted, and narrowed to 0700 as any root wider is
// (TestEnsureAllNarrowsAnOpenRoot). An entry beyond the mode is judged: a named user's, the group's
// right to delete what is in the root, an entry passed on from a directory above or one the root
// passes on to what is made in it, though either grants no more than the write the mode found
// shows (chmod leaves both standing), or a grant the mode found does not show; a deny entry,
// which the old trivial ACL had, takes nothing away.
func TestJudgeLeavesARootsTrivialNFSv4ACLToTheNarrowing(t *testing.T) {
	defer func(was func(string, string) ([]string, error)) { groupUsers = was }(groupUsers)
	groupUsers = func(string, string) ([]string, error) { return []string{"mallory"}, nil }

	// What every trivial entry allows, and what read, write and search add, as FreeBSD numbers them.
	const (
		allow, deny = nfs4Allow, 0x0200
		always      = 0x1000 | 0x0200 | 0x0040 | 0x8000 // read the ACL, attributes and named attributes; synchronize
		owns        = 0x2000 | 0x4000 | 0x0400 | 0x0080 // write the ACL, the owner, attributes and named attributes
		r, w, x     = 0x0008, nfs4AddFile | nfs4AddSubdirectory, 0x0001
		inherited   = 0x0080
		inherits    = 0x0001 | 0x0002 // passed on to the files and the directories made inside
	)

	trivial := func(group, everyone uint32, more ...[5]uint32) []writer {
		t.Helper()

		ws, err := freebsdACL(freebsdBuf(append([][5]uint32{
			{0x01, 0, always | owns | r | w | x, allow},
			{0x04, 0, always | group, allow},
			{0x40, 0, always | everyone, allow},
		}, more...)...), true)
		if err != nil {
			t.Fatal(err)
		}

		return ws
	}

	for _, c := range []struct {
		name    string
		mode    os.FileMode
		acl     []writer
		refused string
	}{
		{"0775's trivial ACL", 0o775, trivial(r|w|x, r|x), ""},
		{"0777's trivial ACL", 0o777, trivial(r|w|x, r|w|x), ""},
		{"0775's, with the old trivial ACL's deny", 0o775, trivial(r|w|x, r|x, [5]uint32{0x40, 0, w, deny}), ""},
		{"0775's, and a named user's write", 0o775, trivial(r|w|x, r|x, [5]uint32{0x02, 1001, nfs4AddFile, allow}),
			"uid 1001"},
		{"0775's, its group deleting what is in it", 0o775, trivial(r|w|x|nfs4DeleteChild, r|x), "its group"},
		{"0777's, and everybody's write passed on", 0o777,
			trivial(r|w|x, r|w|x, [5]uint32{0x40, 0, w, allow, inherited}), "anybody"},
		{"0777's, and everybody's write it passes on", 0o777,
			trivial(r|w|x, r|w|x, [5]uint32{0x40, 0, w, allow, inherits}), "anybody"},
		{"0775's, and its group's write it passes on", 0o775,
			trivial(r|w|x, r|x, [5]uint32{0x04, 0, w, allow, inherits}), "its group"},
		{"a group write the mode found does not show", 0o750, trivial(r|w|x, 0), "its group"},
	} {
		got := judgeRoot(os.ModeDir|c.mode, 0, c.acl, false, os.Geteuid())

		switch {
		case c.refused != "" && !strings.Contains(got, c.refused):
			t.Errorf("%s: judgeRoot = %q, want a refusal naming %s", c.name, got, c.refused)
		case c.refused == "" && got != "":
			t.Errorf("%s: judgeRoot = %q, want nothing", c.name, got)
		}
	}
}

// TestARootsACLIsLeftUnreadOnlyBesideAPOSIXReader ties rootACLMayRefuse, where a platform's file
// makes it false, to the extendedWriters beside it. secure leaves a root's own ACL unread there,
// which loses nothing only while every ACL that reader returns is a POSIX.1e one, reported by its
// aclGroup, which judgeRoot judges at the narrowed 0700 as letting nobody write
// (TestARootsACLCannotRefuseItHere), or none at all. So each of its returns is no ACL, nil and
// false, or a POSIX.1e one, true; a reader of anything else there -- an NFSv4 mount's
// system.nfs4_acl, on Linux -- needs that file's rootACLMayRefuse true. The two are tied by the
// file that holds them, so every file of the package is read, whatever it is named, and one that
// holds either without the other is refused.
func TestARootsACLIsLeftUnreadOnlyBesideAPOSIXReader(t *testing.T) {
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}

	fset := token.NewFileSet()
	unread := 0

	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}

		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}

		mayRefuse, reader := "", (*ast.FuncDecl)(nil)

		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.GenDecl:
				for _, s := range d.Specs {
					if v, ok := s.(*ast.ValueSpec); ok && len(v.Names) == 1 && v.Names[0].Name == "rootACLMayRefuse" &&
						len(v.Values) == 1 {
						mayRefuse = types.ExprString(v.Values[0])
					}
				}
			case *ast.FuncDecl:
				if d.Name.Name == "extendedWriters" {
					reader = d
				}
			}
		}

		if (mayRefuse == "") != (reader == nil) {
			t.Errorf("%s holds one of rootACLMayRefuse and extendedWriters without the other, which this ties by file", name)

			continue
		}

		if mayRefuse != "false" {
			continue
		}

		unread++

		ast.Inspect(reader.Body, func(n ast.Node) bool {
			r, ok := n.(*ast.ReturnStmt)
			if !ok {
				_, closure := n.(*ast.FuncLit)

				return !closure
			}

			if len(r.Results) != 3 {
				t.Errorf("%s: extendedWriters returns at %s what this cannot read", name, fset.Position(r.Pos()))

				return true
			}

			if ws, posix := types.ExprString(r.Results[0]), types.ExprString(r.Results[1]); posix != "true" &&
				(ws != "nil" || posix != "false") {
				t.Errorf("%s: extendedWriters returns %s, %s at %s, an ACL it does not report as POSIX.1e, which can "+
					"refuse a root, so rootACLMayRefuse is true there", name, ws, posix, fset.Position(r.Pos()))
			}

			return true
		})
	}

	if unread == 0 {
		t.Fatal("no platform's file leaves a root's ACL unread, so nothing was held")
	}
}
