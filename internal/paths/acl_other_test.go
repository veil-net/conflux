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
	"syscall"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/group"
)

func mode(t *testing.T, dir string) os.FileMode {
	t.Helper()

	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}

	return fi.Mode().Perm()
}

// TestEnsureAllLeavesTheSharedLogAlone: macOS and FreeBSD write the service's log into the
// system's /var/log, which is not conflux's to change.
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
			defer func(was usersOf) { groups = was }(groups)
			groups = groupsFunc(func(string, string) ([]string, error) { return []string{"mallory"}, nil })

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

		open, err := filepath.EvalSymlinks(filepath.Dir(target))
		if err != nil {
			t.Fatal(err)
		}

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
		a, open, safe := t.TempDir(), realTempDir(t), t.TempDir()
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

// parentsAs refuses dir where its way, walked from / (walk), is not held to parents' rule for euid
// (parentsRuleAs).
func parentsAs(dir string, euid int) error {
	w, err := walk(dir, parentsRuleAs(dir, euid))
	if err == nil {
		w.close()
	}

	return err
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
// conflux inside it, not made yet, and groups answering for any group, until the test
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

	was := groups
	t.Cleanup(func() { groups = was })
	groups = groupsFunc(func(_, gid string) ([]string, error) { return users(gid == own) })

	t.Setenv("CONFLUX_DIR", filepath.Join(parent, "conflux"))

	return parent
}

// realTempDir is t.TempDir as the walk names it, no link on the way to it: a TMPDIR behind a link -- on
// macOS /var/folders, under /private -- is named by where the link leads in what the walk refuses.
func realTempDir(t *testing.T) string {
	t.Helper()

	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	return dir
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

// TestTheWalkJudgesEveryStepOnce: the way is walked as the kernel looks dir up, a link's target read
// from the directory the link is in, ".." included, and each directory a name is looked up in is
// judged once, before the name is looked up, as is each link before it is followed, as itself, and
// not the directory the root resolves to. A directory ".." leads back to is not judged again.
func TestTheWalkJudgesEveryStepOnce(t *testing.T) {
	base := realTempDir(t) // under /private/var on macOS

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

	var judged []string

	links := map[string]bool{}
	record := func(p string, s step, link bool) error {
		if fileLink := s.st.Mode&syscall.S_IFMT == syscall.S_IFLNK; link != fileLink {
			t.Errorf("the walk judged %s as a link %v, but what it holds is %#o", p, link, s.st.Mode)
		}

		judged, links[p] = append(judged, p), link

		return nil
	}

	w, err := walk(filepath.Join(base, "a", "l"), record)
	if err != nil {
		t.Fatal(err)
	}

	if w.missing != nil || w.last().path != filepath.Join(base, "b", "c") {
		t.Errorf("the walk ended at %s, %v, want %s, there", w.last().path, w.missing, filepath.Join(base, "b", "c"))
	}

	w.close()

	for _, want := range []string{"/", base, filepath.Join(base, "a"), filepath.Join(base, "a", "l"),
		filepath.Join(base, "d"), filepath.Join(base, "d", "m"), filepath.Join(base, "b")} {
		if !slices.Contains(judged, want) {
			t.Errorf("the walk did not judge %s: %q", want, judged)
		}
	}

	for i, p := range judged {
		if p == filepath.Join(base, "b", "c") || slices.Contains(judged[:i], p) {
			t.Errorf("the walk judged %s, which is the root or judged already: %q", p, judged)
		}

		if link := p == filepath.Join(base, "a", "l") || p == filepath.Join(base, "d", "m"); links[p] != link {
			t.Errorf("the walk judged %s as a link %v", p, links[p])
		}
	}

	// a/up -> ../d: the walk goes back up to base, which it judged on the way down, and on into d.
	if err := os.Symlink("../d", filepath.Join(base, "a", "up")); err != nil {
		t.Fatal(err)
	}

	judged = nil

	if w, err = walk(filepath.Join(base, "a", "up", "m"), record); err != nil {
		t.Fatal(err)
	}

	w.close()

	if i := slices.Index(judged, filepath.Join(base, "d")); i < 0 || slices.Contains(judged[i+1:], base) {
		t.Errorf("the walk did not judge d, or judged base again after going back up to it: %q", judged)
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

// groupsFunc stands in for groups: who it says each group lets in.
type groupsFunc func(name, gid string) ([]string, error)

func (f groupsFunc) Users(name, gid string) ([]string, error) { return f(name, gid) }

// TestAGroupIsAskedOfTheProcesssLookup: who a group lets in is asked of groups, which is one
// group.Lookup for the whole process, so that each group's record is read once however many
// directories a command or a supervisor's start judges: groupOf asks it at every judgement of a
// directory its group may write, and nothing else.
func TestAGroupIsAskedOfTheProcesssLookup(t *testing.T) {
	if _, ok := groups.(*group.Lookup); !ok {
		t.Fatalf("groups is %T, not one group.Lookup for the process", groups)
	}

	me, err := user.LookupId(strconv.Itoa(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}

	g, err := user.LookupGroupId(me.Gid)
	if err != nil {
		t.Fatal(err)
	}

	was := groups
	t.Cleanup(func() { groups = was })

	var asked []string

	groups = groupsFunc(func(name, gid string) ([]string, error) {
		asked = append(asked, name+":"+gid)

		return []string{me.Username}, nil
	})

	gid, _ := strconv.ParseUint(g.Gid, 10, 32)

	for range 2 {
		if !groupOf(uint32(gid), os.Geteuid()) {
			t.Errorf("groupOf(%s), its one member this account, = false", g.Name)
		}
	}

	if want := []string{g.Name + ":" + g.Gid, g.Name + ":" + g.Gid}; !slices.Equal(asked, want) {
		t.Errorf("groupOf asked groups %q, want %q", asked, want)
	}
}
