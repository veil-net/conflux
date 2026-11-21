//go:build !windows

package paths

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestRemoveRootFollowsNothing: uninstall removes every root, one the readers' check refuses among
// them, so RemoveRoot removes a root and everything in it from the directory the walk to it holds,
// following nothing: a link in it to a directory outside, and one deeper, are removed as links, and a
// root whose own name is a link is that link, removed as itself, with what each led to untouched. A
// CONFLUX_DIR found 0757, which the readers' check refuses, is removed all the same. A root not there
// is nothing removed.
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

	link := filepath.Join(t.TempDir(), "conflux")
	if err := os.Symlink(elsewhere, link); err != nil {
		t.Fatal(err)
	}

	if gone, err := RemoveRoot(link); !gone || err != nil {
		t.Fatalf("RemoveRoot(a link at a root's name) = %v, %v, want the link removed", gone, err)
	}

	if _, err := os.Lstat(link); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the link at %s is there once RemoveRoot removed it (%v)", link, err)
	}

	if _, err := os.Stat(kept); err != nil {
		t.Errorf("RemoveRoot of a link at a root's name removed where it led: %v", err)
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
// (OpenIn), never by its name: a CONFLUX_DIR whose name is a link to a directory every account may
// write is refused, naming the link, before anything in that directory is opened, though the link is
// this account's and the way to it passes; one leading to a directory of this account's own at 0700
// is followed, and what is in it read.
func TestARootIsHeldBeforeAnythingInItIsOpened(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	root := filepath.Join(base, "conflux")
	t.Setenv("CONFLUX_DIR", root)

	d := Default()

	for _, c := range []struct {
		name string
		mode os.FileMode
		ok   bool
	}{
		{"a directory every account may write", 0o777, false},
		{"a directory of this account's own", 0o700, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			target := t.TempDir()

			for name, body := range map[string]string{wayName: base + "\n", "serve.lock": ""} {
				if err := os.WriteFile(filepath.Join(target, name), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			if err := os.Chmod(target, c.mode); err != nil {
				t.Fatal(err)
			}

			if err := os.Symlink(target, root); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.Remove(root) })

			way, err := d.Way()

			switch {
			case c.ok && (err != nil || !slices.Equal(way, []string{base})):
				t.Errorf("Way(), the root a link to %s = %q, %v, want it read through the link", c.name, way, err)
			case !c.ok && (err == nil || !strings.Contains(err.Error(), root+" is a link to "+target)):
				t.Errorf("Way(), the root a link to %s = %q, %v, want a refusal naming the link", c.name, way, err)
			}

			f, err := d.OpenIn(d.ServeLockFile())
			if err == nil {
				f.Close()
			}

			switch {
			case c.ok && err != nil:
				t.Errorf("OpenIn(the serve lock), the root a link to %s = %v, want it opened", c.name, err)
			case !c.ok && (err == nil || !strings.Contains(err.Error(), root+" is a link to "+target)):
				t.Errorf("OpenIn(the serve lock), the root a link to %s = %v, want a refusal naming the link", c.name,
					err)
			}
		})
	}
}
