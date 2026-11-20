//go:build !windows

package paths

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
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
		root := filepath.Join(t.TempDir(), "conflux")
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}

		err := parentsAs(root, os.Geteuid()+1)
		if err == nil || !strings.Contains(err.Error(), "belongs to uid") {
			t.Errorf("a root in a directory another uid owns was accepted, or the refusal does not say why: %v", err)
		}
	})

	// A root that is a link is held to the directories above where it leads, too.
	t.Run("a link into one", func(t *testing.T) {
		open := t.TempDir()
		if err := os.Mkdir(filepath.Join(open, "conflux"), 0o700); err != nil {
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
		if err := os.Symlink(filepath.Join(open, "conflux"), link); err != nil {
			t.Fatal(err)
		}

		t.Setenv("CONFLUX_DIR", link)

		if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), open) {
			t.Errorf("a link into a directory anybody may write was accepted, or the refusal does not name it: %v", err)
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
		refused bool
	}{
		{name: "this account alone", users: []string{me.Username}},
		{name: "nobody", users: nil},
		{name: "this account and another", users: []string{me.Username, "mallory"}, refused: true},
		{name: "an answer the database cannot give", err: errors.New("getent group: exit status 2"), refused: true},
	} {
		t.Run(c.name, func(t *testing.T) {
			defer func(was func(string, string) ([]string, error)) { groupUsers = was }(groupUsers)
			groupUsers = func(string, string) ([]string, error) { return c.users, c.err }

			parent := t.TempDir()
			if err := os.Mkdir(filepath.Join(parent, "conflux"), 0o700); err != nil {
				t.Fatal(err)
			}

			if err := os.Chmod(parent, 0o770); err != nil {
				t.Fatal(err)
			}

			t.Setenv("CONFLUX_DIR", filepath.Join(parent, "conflux"))

			switch err := Default().EnsureAll(); {
			case c.refused && (err == nil || !strings.Contains(err.Error(), "its group")):
				t.Errorf("a root its group may write, the group letting in %q, was accepted, or not for that: %v", c.users, err)
			case !c.refused && err != nil:
				t.Errorf("a root its group may write, the group letting in %q, was refused: %v", c.users, err)
			}
		})
	}
}
