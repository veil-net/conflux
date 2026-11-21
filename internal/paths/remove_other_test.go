//go:build !windows

package paths

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestRemoveRootFollowsNothing: uninstall removes every root, one the readers' check refuses among
// them, so RemoveRoot removes a root and everything in it from the directory the walk to it holds,
// following nothing: a link in it to a directory outside, and one deeper, are removed as links, with
// what each led to untouched. A CONFLUX_DIR found 0757, which the readers' check refuses, is removed
// all the same. A root not there is nothing removed.
func TestRemoveRootFollowsNothing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "conflux")
	t.Setenv("CONFLUX_DIR", root)

	d := Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	elsewhere := t.TempDir()

	kept := filepath.Join(elsewhere, "kept")
	if err := os.WriteFile(kept, []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, link := range []string{filepath.Join(root, "conflux.json"), filepath.Join(d.Run, "anchord")} {
		if err := os.Symlink(elsewhere, link); err != nil {
			t.Fatal(err)
		}
	}

	if err := os.Chmod(root, 0o757); err != nil {
		t.Fatal(err)
	}

	if err := d.Check(); err == nil {
		t.Fatalf("Check(a CONFLUX_DIR at 0757) = nil, want the readers' refusal this is about")
	}

	if gone, err := RemoveRoot(root); !gone || err != nil {
		t.Fatalf("RemoveRoot(%s) = %v, %v, want it removed", root, gone, err)
	}

	if _, err := os.Lstat(root); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s is there once RemoveRoot removed it (%v)", root, err)
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

// TestRemoveRootFollowsALinkRootOnlyWhereConfluxWould: a root whose own name is a link -- one moved to
// another disk -- is gone into only where conflux would follow it in daily use, to a directory conflux
// has secured as a root, as it has every working installation's, a platform root's and a CONFLUX_DIR's
// alike: a link of this account's to a directory of its own at 0700 is followed, what that directory
// holds removed through the handle held on it, a link in it as itself, and then the link, the
// directory left empty; a link to a directory of this account's own at 0777, which conflux has not
// secured, to one another account owns, and to the directory it is in, are removed as themselves, with
// where each leads left as it was.
func TestRemoveRootFollowsALinkRootOnlyWhereConfluxWould(t *testing.T) {
	elsewhere := t.TempDir()

	kept := filepath.Join(elsewhere, "kept")
	if err := os.WriteFile(kept, []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}

	plant := func(dir string) {
		if err := os.WriteFile(filepath.Join(dir, "manifest.b64"), []byte("identity"), 0o600); err != nil {
			t.Fatal(err)
		}

		if err := os.Symlink(elsewhere, filepath.Join(dir, "anchor")); err != nil {
			t.Fatal(err)
		}
	}

	for _, chosen := range []bool{false, true} {
		for _, c := range []struct {
			name   string
			target func(t *testing.T, in string) (string, bool)
			follow bool
		}{
			{"a directory of this account's own", func(t *testing.T, _ string) (string, bool) {
				return ours(t, 0o700, plant), true
			}, true},
			{"a directory of this account's own every account may write", func(t *testing.T, _ string) (string, bool) {
				return ours(t, 0o777, plant), true
			}, false},
			{"a directory another account owns", func(t *testing.T, _ string) (string, bool) { return theirs(t, plant) },
				false},
			{"the directory it is in", func(_ *testing.T, in string) (string, bool) { plant(in); return in, true }, false},
		} {
			t.Run(fmt.Sprintf("%s, a CONFLUX_DIR %v", c.name, chosen), func(t *testing.T) {
				in, err := filepath.EvalSymlinks(t.TempDir())
				if err != nil {
					t.Fatal(err)
				}

				root := filepath.Join(in, "conflux")

				t.Setenv("CONFLUX_DIR", "")
				if chosen {
					t.Setenv("CONFLUX_DIR", root)
				}

				target, planted := c.target(t, in)

				if err := os.Symlink(target, root); err != nil {
					t.Fatal(err)
				}

				if gone, err := RemoveRoot(root); !gone || err != nil {
					t.Fatalf("RemoveRoot(a link at a root's name to %s) = %v, %v, want it removed", c.name, gone, err)
				}

				if _, err := os.Lstat(root); !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("the link at %s is there once RemoveRoot removed it (%v)", root, err)
				}

				if _, err := os.Lstat(target); err != nil {
					t.Fatalf("RemoveRoot of a link to %s removed where it led: %v", c.name, err)
				}

				if entries, err := os.ReadDir(target); planted {
					switch {
					case err != nil:
						t.Errorf("read %s: %v", target, err)
					case c.follow && len(entries) != 0:
						t.Errorf("RemoveRoot of a link to %s left %v there, want it emptied", c.name, entries)
					case !c.follow && len(entries) != 2:
						t.Errorf("RemoveRoot of a link to %s left %v there, want it untouched", c.name, entries)
					}
				}

				if b, err := os.ReadFile(kept); err != nil || string(b) != "kept" {
					t.Errorf("RemoveRoot reached %s through a link in where a link at a root's name led: %q, %v", kept,
						b, err)
				}
			})
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

	root := filepath.Join(open, "conflux")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONFLUX_DIR", root)

	if err := Default().JudgeWays(); err == nil || !strings.Contains(err.Error(), open) {
		t.Errorf("JudgeWays(a CONFLUX_DIR inside a directory anybody may write) = %v, want a refusal naming it", err)
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

// TestTheWayConfluxMadeIsRemovedWhenEmpty: EnsureAll records each folder it made on the way to an
// installation's root, in the state root, once, however often it runs; Way reads the record back,
// deepest first, keeping only folders above one of the roots, where the readers' check refuses the
// state root too, and refuses a record that is a link, unfollowed. Once the root is gone, RemoveWay removes each recorded folder that is empty,
// deepest first, and leaves one holding anything else, and a link put at a recorded folder's name. An
// ephemeral run's roots keep no record.
func TestTheWayConfluxMadeIsRemovedWhenEmpty(t *testing.T) {
	base := t.TempDir()
	a, b := filepath.Join(base, "a"), filepath.Join(base, "a", "b")
	root := filepath.Join(b, "conflux")

	t.Setenv("CONFLUX_DIR", root)
	d := Default()

	for range 2 {
		if err := d.EnsureAll(); err != nil {
			t.Fatal(err)
		}
	}

	record := filepath.Join(d.State, wayName)

	if got, err := d.readWay(); err != nil || !slices.Equal(got, []string{a, b}) {
		t.Fatalf("the record EnsureAll kept = %q, %v, want %q, each once", got, err, []string{a, b})
	}

	elsewhere := t.TempDir()
	if err := os.WriteFile(record, []byte(a+"\n"+b+"\n"+elsewhere+"\nrelative\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	way, err := d.Way()
	if err != nil || !slices.Equal(way, []string{b, a}) {
		t.Fatalf("Way() = %q, %v, want %q, deepest first, and nothing not above a root", way, err, []string{b, a})
	}

	if err := os.Chmod(root, 0o757); err != nil {
		t.Fatal(err)
	}

	if got, err := d.Way(); err != nil || !slices.Equal(got, way) {
		t.Errorf("Way() of a state root the readers' check refuses = %q, %v, want %q all the same", got, err, way)
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

	other := filepath.Join(a, "other")
	if err := os.WriteFile(other, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := RemoveRoot(root); err != nil {
		t.Fatal(err)
	}

	if removed, err := RemoveWay(way); err != nil || !slices.Equal(removed, []string{b}) {
		t.Errorf("RemoveWay(%q), %s holding a file = %q, %v, want %q", way, a, removed, err, []string{b})
	}

	if err := os.Remove(other); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(elsewhere, b); err != nil {
		t.Fatal(err)
	}

	if removed, err := RemoveWay(way); err != nil || removed != nil {
		t.Errorf("RemoveWay(%q), a link at %s = %q, %v, want nothing removed", way, b, removed, err)
	}

	if _, err := os.Lstat(b); err != nil {
		t.Errorf("RemoveWay removed the link at %s: %v", b, err)
	}

	if err := os.Remove(b); err != nil {
		t.Fatal(err)
	}

	if removed, err := RemoveWay(way); err != nil || !slices.Equal(removed, []string{a}) {
		t.Errorf("RemoveWay(%q) = %q, %v, want %q", way, removed, err, []string{a})
	}

	if _, err := os.Stat(elsewhere); err != nil {
		t.Errorf("RemoveWay reached %s: %v", elsewhere, err)
	}

	e := EphemeralDirs(filepath.Join(base, "x", "conflux-ephemeral"))
	if err := e.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Lstat(filepath.Join(e.State, wayName)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("EnsureAll of an ephemeral run's roots kept a record of its way (%v)", err)
	}
}

// TestARootIsHeldBeforeAnythingInItIsOpened: what is read in a root before anything has judged it --
// the way record uninstall reads, the serve lock tidy asks after -- is opened through the root held
// (OpenIn), never by its name: a CONFLUX_DIR whose name is a link to a directory another account owns
// is refused, naming the link, before anything in that directory is opened, though the link is this
// account's and the way to it passes; one leading to a directory of this account's own is followed,
// and what is in it read, at 0700 and at a 0777 EnsureAll would narrow, as it narrows a root at the
// name itself.
func TestARootIsHeldBeforeAnythingInItIsOpened(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	root := filepath.Join(base, "conflux")
	t.Setenv("CONFLUX_DIR", root)

	d := Default()

	plant := func(dir string) {
		for name, body := range map[string]string{wayName: base + "\n", "serve.lock": ""} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}

	for _, c := range []struct {
		name   string
		target func(t *testing.T) string
		ok     bool
	}{
		{"a directory of this account's own", func(t *testing.T) string { return ours(t, 0o700, plant) }, true},
		{"a directory of this account's own every account may write", func(t *testing.T) string {
			return ours(t, 0o777, plant)
		}, true},
		{"a directory another account owns", func(t *testing.T) string { dir, _ := theirs(t, plant); return dir }, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			target := c.target(t)

			if err := os.Symlink(target, root); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Remove(root) })

			way, err := d.Way()

			switch {
			case c.ok && (err != nil || !slices.Equal(way, []string{base})):
				t.Errorf("Way(), the root a link to %s = %q, %v, want it read through the link", c.name, way, err)
			case !c.ok && (err == nil || !strings.Contains(err.Error(), root+" is a link to ")):
				t.Errorf("Way(), the root a link to %s = %q, %v, want a refusal naming the link", c.name, way, err)
			}

			f, err := d.OpenIn(d.ServeLockFile())
			if err == nil {
				f.Close()
			}

			switch {
			case c.ok && err != nil:
				t.Errorf("OpenIn(the serve lock), the root a link to %s = %v, want it opened", c.name, err)
			case !c.ok && (err == nil || !strings.Contains(err.Error(), root+" is a link to ")):
				t.Errorf("OpenIn(the serve lock), the root a link to %s = %v, want a refusal naming the link", c.name,
					err)
			}
		})
	}
}

// ours is a directory of this account's own at mode, with plant called on it first.
func ours(t *testing.T, mode os.FileMode, plant func(dir string)) string {
	t.Helper()

	dir := t.TempDir()
	plant(dir)

	if err := os.Chmod(dir, mode); err != nil {
		t.Fatal(err)
	}

	return dir
}

// theirs is a directory another account owns, and whether plant was called on it: where this test runs
// as root, one made, planted and given to nobody (65534); otherwise one already there, in a directory
// root owns that nobody else may write, planted with nothing. The test is skipped where there is none.
func theirs(t *testing.T, plant func(dir string)) (string, bool) {
	t.Helper()

	euid := os.Geteuid()

	if euid == 0 {
		dir := filepath.Join(t.TempDir(), "theirs")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}

		plant(dir)

		if err := filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
			if err != nil {
				return err
			}

			return os.Lchown(p, 65534, 65534)
		}); err != nil {
			t.Fatal(err)
		}

		return dir, true
	}

	owner := func(p string) (uint32, os.FileInfo, bool) {
		fi, err := os.Lstat(p)
		if err != nil {
			return 0, nil, false
		}

		st, ok := fi.Sys().(*syscall.Stat_t)

		return st.Uid, fi, ok
	}

	for _, parent := range []string{"/var/lib", "/var/cache", "/var/spool", "/var/db", "/home", "/Users"} {
		if uid, fi, ok := owner(parent); !ok || uid != 0 || !fi.IsDir() || fi.Mode().Perm()&0o022 != 0 {
			continue
		}

		entries, _ := os.ReadDir(parent)
		for _, e := range entries {
			p := filepath.Join(parent, e.Name())
			if uid, fi, ok := owner(p); ok && fi.IsDir() && uid != 0 && int(uid) != euid {
				return p, false
			}
		}
	}

	t.Skip("no directory another account owns is here in a directory only root may write, and only root can " +
		"make one")

	return "", false
}

// TestTheWayIsJudgedBeforeItIsReadOrRemoved: a CONFLUX_DIR's way is held to parents' rule before the
// record in it is read (Way) and before a folder recorded above it is removed (RemoveWay), since a way
// another account may change could lead either elsewhere: with a directory every account may write
// on it, Way refuses, naming that directory, and RemoveWay refuses, naming it, and leaves the folder;
// a folder above no CONFLUX_DIR, on a platform root's way, is not judged, and is removed.
func TestTheWayIsJudgedBeforeItIsReadOrRemoved(t *testing.T) {
	open, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	a := filepath.Join(open, "a")
	root := filepath.Join(a, "conflux")

	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(root, wayName), []byte(a+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONFLUX_DIR", root)

	if way, err := Default().Way(); err != nil || !slices.Equal(way, []string{a}) {
		t.Fatalf("Way(), its way this account's alone = %q, %v, want %q", way, err, []string{a})
	}

	if err := os.Chmod(open, 0o777); err != nil {
		t.Fatal(err)
	}

	if way, err := Default().Way(); err == nil || !strings.Contains(err.Error(), "inside "+open) {
		t.Errorf("Way(), a directory every account may write on its way = %q, %v, want a refusal naming it", way, err)
	}

	if err := os.RemoveAll(root); err != nil {
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
	root := filepath.Join(base, "conflux")

	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONFLUX_DIR", root)

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
