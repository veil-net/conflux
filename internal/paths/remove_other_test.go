//go:build !windows

package paths

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestRemoveRootFollowsNothing: uninstall removes every root, one the readers' check refuses among
// them, so RemoveRoot removes a root and everything in it from the directory the walk to it holds,
// following nothing: a link in it to a directory outside, and one deeper, are removed as links, with
// what each led to untouched, and so is a link at the root's own name. A root found 0757, which the
// readers' check refuses, is removed all the same, and the CONFLUX_DIR it is in is left. A root not
// there is nothing removed.
func TestRemoveRootFollowsNothing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "conflux")
	t.Setenv("CONFLUX_DIR", dir)

	d := Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	root := d.State

	elsewhere := t.TempDir()

	kept := filepath.Join(elsewhere, "kept")
	if err := os.WriteFile(kept, []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, link := range []string{d.ConfigFile(), filepath.Join(d.Run, "anchord")} {
		if err := os.Symlink(elsewhere, link); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.Chmod(root, 0o757); err != nil {
		t.Fatal(err)
	}

	if err := d.Check(); err == nil {
		t.Fatalf("Check(a root at 0757) = nil, want the readers' refusal this is about")
	}

	if gone, err := RemoveRoot(root); !gone || err != nil {
		t.Fatalf("RemoveRoot(%s) = %v, %v, want it removed", root, gone, err)
	}

	if _, err := os.Lstat(root); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s is there once RemoveRoot removed it (%v)", root, err)
	}

	if _, err := os.Lstat(dir); err != nil {
		t.Errorf("RemoveRoot removed the CONFLUX_DIR %s its root was in: %v", dir, err)
	}

	if err := os.Symlink(elsewhere, root); err != nil {
		t.Fatal(err)
	}

	if gone, err := RemoveRoot(root); !gone || err != nil {
		t.Fatalf("RemoveRoot(%s, a link) = %v, %v, want it removed", root, gone, err)
	}

	if _, err := os.Lstat(root); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the link %s is there once RemoveRoot removed it (%v)", root, err)
	}

	if b, err := os.ReadFile(kept); err != nil || string(b) != "kept" {
		t.Errorf("RemoveRoot reached %s through a link: %q, %v", kept, b, err)
	}

	for _, absent := range []string{root, filepath.Join(t.TempDir(), "not", "there")} {
		if gone, err := RemoveRoot(absent); gone || err != nil {
			t.Errorf("RemoveRoot(%s, which is not there) = %v, %v, want nothing removed", absent, gone, err)
		}
	}
}

// TestRemoveRootHoldsACONFLUXDIRsWay: a CONFLUX_DIR's way is held to parents' rule before anything in
// it is removed, as the readers' check holds it, since a way another account may change could lead the
// removal elsewhere: one inside a directory every account may write is refused, naming that
// directory, and left, and JudgeWays, the same judgement with nothing removed, refuses it alike, and
// takes it once the directory is this account's alone. A platform root's way is not judged, as it is
// not when the root is made, and the root is removed.
func TestRemoveRootHoldsACONFLUXDIRsWay(t *testing.T) {
	open := t.TempDir()
	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONFLUX_DIR", filepath.Join(open, "conflux"))

	root := Default().State
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := Default().JudgeWays(); !errors.Is(err, ErrWayRefused) || !strings.Contains(err.Error(), open) {
		t.Errorf("JudgeWays(a CONFLUX_DIR inside a directory anybody may write) = %v, want a refusal of its way "+
			"naming it", err)
	}

	if gone, err := RemoveRoot(root); gone || err == nil || !strings.Contains(err.Error(), open) {
		t.Errorf("RemoveRoot(a CONFLUX_DIR inside a directory anybody may write) = %v, %v, want a refusal naming it",
			gone, err)
	}

	if err := os.Chmod(open, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := Default().JudgeWays(); err != nil {
		t.Errorf("JudgeWays(a CONFLUX_DIR whose way is this account's alone) = %v", err)
	}

	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONFLUX_DIR", filepath.Join(t.TempDir(), "not", "there", "conflux"))

	if err := Default().JudgeWays(); err != nil {
		t.Errorf("JudgeWays(a CONFLUX_DIR whose way is not there) = %v", err)
	}

	if _, err := os.Lstat(root); err != nil {
		t.Errorf("RemoveRoot refusing a CONFLUX_DIR's way removed it: %v", err)
	}

	t.Setenv("CONFLUX_DIR", "")

	if err := (Dirs{Config: root, State: root}).JudgeWays(); err != nil {
		t.Errorf("JudgeWays(a platform root inside a directory anybody may write) = %v, want its way not judged", err)
	}

	if gone, err := RemoveRoot(root); !gone || err != nil {
		t.Errorf("RemoveRoot(a platform root inside a directory anybody may write) = %v, %v, want it removed", gone, err)
	}
}

// TestTheWayConfluxMadeIsRemovedWhole: EnsureAll records each folder it made on the way to an
// installation's root, in the state root, once, however often it runs, the CONFLUX_DIR among them where
// it made that too; Way reads the record back, deepest first, keeping only folders above one of the
// roots and none at the top of a volume, reads none where the readers' check refuses the state root,
// whose record is none of conflux's either, and refuses a record that is a link, unfollowed. RemoveWay
// leaves each folder holding a root of conflux's that is there, and once the root is gone removes each
// recorded folder whole, deepest first, whatever it holds, the folder they were made in kept; a link
// put at a recorded folder's name is left, and where it leads untouched. An ephemeral run's root keeps
// the record of the folders made on the way to it alike, and RemoveEmptyWay removes a .conflux it made,
// the installation's root by its name, where it is empty, and leaves it where it holds an installation.
func TestTheWayConfluxMadeIsRemovedWhole(t *testing.T) {
	base := t.TempDir()
	a, b := filepath.Join(base, "a"), filepath.Join(base, "a", "b")
	dir := filepath.Join(b, "conflux")

	t.Setenv("CONFLUX_DIR", dir)
	d := Default()
	root := d.State

	for range 2 {
		if err := d.EnsureAll(); err != nil {
			t.Fatal(err)
		}
	}

	record := filepath.Join(d.State, wayName)

	if got, err := d.readWay(); err != nil || !slices.Equal(got, []string{a, b, dir}) {
		t.Fatalf("the record EnsureAll kept = %q, %v, want %q, each once", got, err, []string{a, b, dir})
	}

	elsewhere := t.TempDir()
	if err := os.WriteFile(record, []byte("/\n"+a+"\n"+b+"\n"+dir+"\n"+elsewhere+"\nrelative\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	way, err := d.Way()
	if err != nil || !slices.Equal(way, []string{dir, b, a}) {
		t.Fatalf("Way() = %q, %v, want %q, deepest first, and nothing not above a root", way, err, []string{dir, b, a})
	}

	if err := os.Chmod(root, 0o757); err != nil {
		t.Fatal(err)
	}

	if got, err := d.Way(); err != nil || got != nil {
		t.Errorf("Way() of a state root the readers' check refuses = %q, %v, want no record", got, err)
	}

	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}

	kept := filepath.Join(t.TempDir(), "kept")
	if err := os.WriteFile(kept, []byte(a+"\n"+b+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Rename(record, record+".was"); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(kept, record); err != nil {
		t.Fatal(err)
	}

	if got, err := d.Way(); err == nil {
		t.Errorf("Way() of a record that is a link = %q, nil, want it refused, unfollowed", got)
	}

	if err := os.Remove(record); err != nil {
		t.Fatal(err)
	}

	if err := os.Rename(record+".was", record); err != nil {
		t.Fatal(err)
	}

	if removed, err := RemoveWay(way); err != nil || removed != nil {
		t.Errorf("RemoveWay(%q), the root %s there = %q, %v, want nothing removed", way, root, removed, err)
	}

	other := filepath.Join(a, "other")
	if err := os.WriteFile(other, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := RemoveRoot(root); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(elsewhere, dir+".link"); err != nil {
		t.Fatal(err)
	}

	if removed, err := RemoveWay([]string{dir + ".link"}); err != nil || removed != nil {
		t.Errorf("RemoveWay(a link at a recorded name) = %q, %v, want nothing removed", removed, err)
	}

	if _, err := os.Lstat(dir + ".link"); err != nil {
		t.Errorf("RemoveWay removed the link at %s: %v", dir+".link", err)
	}

	if err := os.Remove(dir + ".link"); err != nil {
		t.Fatal(err)
	}

	if removed, err := RemoveWay(way); err != nil || !slices.Equal(removed, way) {
		t.Errorf("RemoveWay(%q), %s holding a file = %q, %v, want each removed", way, a, removed, err)
	}

	if _, err := os.Lstat(a); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("RemoveWay left %s, which holds a file (Lstat: %v)", a, err)
	}

	if _, err := os.Stat(base); err != nil {
		t.Errorf("RemoveWay removed %s, which conflux did not make: %v", base, err)
	}

	if _, err := os.Stat(elsewhere); err != nil {
		t.Errorf("RemoveWay reached %s: %v", elsewhere, err)
	}

	x := filepath.Join(base, "x")

	e := EphemeralDirs(filepath.Join(x, "conflux-ephemeral"))
	if err := e.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	if got, err := e.Way(); err != nil || !slices.Equal(got, []string{x}) {
		t.Errorf("Way() of an ephemeral run's root = %q, %v, want %q", got, err, []string{x})
	}

	t.Setenv("CONFLUX_DIR", t.TempDir())

	installation := Default()

	e = EphemeralDirs(filepath.Join(installation.State, "ephemeral"))
	if err := e.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	eway, err := e.Way()
	if err != nil || !slices.Equal(eway, []string{installation.State}) {
		t.Fatalf("Way() of an ephemeral run's root in a CONFLUX_DIR = %q, %v, want %q", eway, err,
			[]string{installation.State})
	}

	if _, err := RemoveRoot(e.State); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(installation.ConfigFile(), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}

	if removed, err := RemoveEmptyWay(eway); err != nil || removed != nil {
		t.Errorf("RemoveEmptyWay(%q), an installation made there = %q, %v, want nothing removed", eway, removed, err)
	}

	if err := os.Remove(installation.ConfigFile()); err != nil {
		t.Fatal(err)
	}

	if removed, err := RemoveEmptyWay(eway); err != nil || !slices.Equal(removed, eway) {
		t.Errorf("RemoveEmptyWay(%q), empty = %q, %v, want it removed", eway, removed, err)
	}
}

// TestARootIsHeldBeforeAnythingInItIsOpened: what is read in a root by a command that has not made it --
// the way record uninstall reads, the serve lock tidy asks after -- is opened through the root held
// (OpenIn), never by its name, and only where what is at the root's name is as conflux makes a root
// (ours): a directory of this account's own at 0700 is read, and a link at the name -- to a directory of
// this account's own, the directory it is in, or nothing -- is none of conflux's, and taken as no root
// at all, nothing in it opened; and so is a directory of this account's own every account may write, the
// way record in it among what is not read.
func TestARootIsHeldBeforeAnythingInItIsOpened(t *testing.T) {
	base := realTempDir(t)

	t.Setenv("CONFLUX_DIR", base)

	d := Default()
	root := d.State

	plant := func(dir string) {
		for name, body := range map[string]string{wayName: base + "\n", "serve.lock": ""} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}

	for _, c := range []struct {
		name    string
		make    func(t *testing.T)
		ok, way bool
	}{
		{"a directory of this account's own", func(t *testing.T) {
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}

			plant(root)
		}, true, true},
		{"a directory of this account's own every account may write", func(t *testing.T) {
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}

			plant(root)

			if err := os.Chmod(root, 0o777); err != nil {
				t.Fatal(err)
			}
		}, false, false},
		{"a link to a directory of this account's own", func(t *testing.T) {
			if err := os.Symlink(mine(t, 0o700, plant), root); err != nil {
				t.Fatal(err)
			}
		}, false, false},
		{"a link to the directory it is in", func(t *testing.T) {
			plant(base)

			if err := os.Symlink(base, root); err != nil {
				t.Fatal(err)
			}
		}, false, false},
		{"a link to nothing", func(t *testing.T) {
			if err := os.Symlink(filepath.Join(base, "missing"), root); err != nil {
				t.Fatal(err)
			}
		}, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			c.make(t)
			t.Cleanup(func() { os.RemoveAll(root) })

			way, err := d.Way()

			switch {
			case c.way && (err != nil || !slices.Equal(way, []string{base})):
				t.Errorf("Way(), the root %s = %q, %v, want it read", c.name, way, err)
			case !c.way && (err != nil || way != nil):
				t.Errorf("Way(), the root %s = %q, %v, want no record", c.name, way, err)
			}

			f, err := d.OpenIn(d.ServeLockFile())
			if err == nil {
				f.Close()
			}

			switch {
			case c.ok && err != nil:
				t.Errorf("OpenIn(the serve lock), the root %s = %v, want it opened", c.name, err)
			case !c.ok && !errors.Is(err, fs.ErrNotExist):
				t.Errorf("OpenIn(the serve lock), the root %s = %v, want none of conflux's", c.name, err)
			}

			switch err := d.Check(); {
			case c.ok && err != nil:
				t.Errorf("Check(), the root %s = %v, want it taken", c.name, err)
			case !c.ok && (err == nil || !strings.Contains(err.Error(), root+" is not as conflux makes")):
				t.Errorf("Check(), the root %s = %v, want a refusal naming it", c.name, err)
			}
		})
	}
}

// TestOursHoldsARootToItsOwnerAndWriters: a directory at a root's name is as conflux makes one where root
// or this account owns it and nobody else may write it, by its mode as fstat read it where the walk met
// it: 0700, the 0710 the supervisor gives the state and run directories, and 0755 are; 0777, 01777 and
// another account's are not -- judged here from a constructed step, an owner of this test's making, so
// on every machine and as every account.
func TestOursHoldsARootToItsOwnerAndWriters(t *testing.T) {
	dir := t.TempDir()
	me := uint32(os.Geteuid())

	for _, c := range []struct {
		uid  uint32
		mode uint32
		ok   bool
	}{
		{me, 0o700, true}, {me, 0o710, true}, {me, 0o755, true}, {0, 0o700, true},
		{me, 0o777, false}, {me, 0o1777, false}, {me + 1, 0o700, me+1 == 0},
	} {
		s := step{st: unix.Stat_t{Uid: c.uid}}
		reflect.ValueOf(&s.st.Mode).Elem().SetUint(uint64(unix.S_IFDIR | c.mode)) // uint16 on macOS and the BSDs

		why, err := ours(dir, s, true)
		if err != nil || (why == "") != c.ok {
			t.Errorf("ours(uid %d, %#o) = %q, %v, want it ours: %v", c.uid, c.mode, why, err, c.ok)
		}
	}
}

// mine is a directory of this account's own at mode, with plant called on it first.
func mine(t *testing.T, mode os.FileMode, plant func(dir string)) string {
	t.Helper()

	dir := t.TempDir()
	plant(dir)

	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}

	return dir
}

// TestTheWayIsJudgedBeforeItIsReadOrRemoved: a CONFLUX_DIR's way is held to parents' rule before the
// record in it is read (Way) and before a folder recorded above it is removed (RemoveWay), since a way
// another account may change could lead either elsewhere: with a directory every account may write
// on it, Way refuses, naming that directory, and RemoveWay refuses, naming it, and leaves the folder;
// a folder above no CONFLUX_DIR, on a platform root's way, is not judged, and is removed.
func TestTheWayIsJudgedBeforeItIsReadOrRemoved(t *testing.T) {
	open := realTempDir(t)

	a := filepath.Join(open, "a")
	t.Setenv("CONFLUX_DIR", filepath.Join(a, "conflux"))

	root := Default().State
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(root, wayName), []byte(a+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if way, err := Default().Way(); err != nil || !slices.Equal(way, []string{a}) {
		t.Fatalf("Way(), its way this account's alone = %q, %v, want %q", way, err, []string{a})
	}

	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}

	if way, err := Default().Way(); err == nil || !strings.Contains(err.Error(), "inside "+open) {
		t.Errorf("Way(), a directory every account may write on its way = %q, %v, want a refusal naming it", way, err)
	}

	if err := os.RemoveAll(Root()); err != nil {
		t.Fatal(err)
	}

	if removed, err := RemoveWay([]string{a}); removed != nil || err == nil || !strings.Contains(err.Error(), open) {
		t.Errorf("RemoveWay(%s, above a CONFLUX_DIR inside a directory every account may write) = %q, %v, want a "+
			"refusal naming it", a, removed, err)
	}

	if _, err := os.Lstat(a); err != nil {
		t.Errorf("RemoveWay refusing the way removed %s: %v", a, err)
	}

	t.Setenv("CONFLUX_DIR", "")

	if removed, err := RemoveWay([]string{a}); err != nil || !slices.Equal(removed, []string{a}) {
		t.Errorf("RemoveWay(%s, above no CONFLUX_DIR) = %q, %v, want it removed, its way not judged", a, removed, err)
	}
}

// TestTheRecordIsReadOnlyAsAPlainFile: the record of the way is read as a file another account may have
// put there, and refused, unread, where it is not one plain file of at most wayMax bytes: a second name
// for a file elsewhere, a record past the size, and a FIFO, which is not waited on.
func TestTheRecordIsReadOnlyAsAPlainFile(t *testing.T) {
	base := t.TempDir()
	t.Setenv("CONFLUX_DIR", filepath.Join(base, "conflux"))

	root := Default().State
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}

	record := filepath.Join(root, wayName)

	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(elsewhere, []byte(base+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for name, plant := range map[string]func() error{
		"a second name":    func() error { return os.Link(elsewhere, record) },
		"past the size":    func() error { return os.WriteFile(record, bytes.Repeat([]byte("x"), wayMax+1), 0o600) },
		"a FIFO":           func() error { return syscall.Mkfifo(record, 0o600) },
		"one plain record": func() error { return os.WriteFile(record, []byte(base+"\n"), 0o600) },
	} {
		if err := plant(); err != nil {
			t.Fatal(err)
		}

		done := make(chan error, 1)

		go func() {
			_, err := Default().Way()
			done <- err
		}()

		select {
		case err := <-done:
			switch {
			case name == "one plain record" && err != nil:
				t.Errorf("Way(), %s = %v", name, err)
			case name != "one plain record" && (err == nil || !strings.Contains(err.Error(), "not a plain file")):
				t.Errorf("Way(), the record %s = %v, want it refused, unread", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("Way(), the record %s, did not return", name)
		}

		if err := os.Remove(record); err != nil {
			t.Fatal(err)
		}
	}
}

// TestOpenInReadsThroughTheRootHeld: what OpenIn opens is looked up in the root it holds, and not by its
// name, so a root put at the name once OpenIn holds the one there -- the one held moved aside, another
// made in its place holding a lock of its own -- answers for nothing: what is read is the held root's.
func TestOpenInReadsThroughTheRootHeld(t *testing.T) {
	root := filepath.Join(t.TempDir(), "conflux")
	t.Setenv("CONFLUX_DIR", root)

	d := Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(d.ServeLockFile(), []byte("held"), 0o600); err != nil {
		t.Fatal(err)
	}

	was := opening
	t.Cleanup(func() { opening = was })

	opening = func(dir string) {
		if err := os.Rename(dir, dir+".was"); err != nil {
			t.Fatal(err)
		}

		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(d.ServeLockFile(), []byte("put there"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	f, err := d.OpenIn(d.ServeLockFile())
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	if b, err := io.ReadAll(f); err != nil || string(b) != "held" {
		t.Errorf("OpenIn(the serve lock), another root put at the name once it held the one there, read %q, %v, want "+
			"the held root's", b, err)
	}
}
