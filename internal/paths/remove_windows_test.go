package paths

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/veil-net/conflux/internal/privtest"
)

// TestRemoveRootFollowsNothing: uninstall removes every root, one the readers' check refuses among
// them, so RemoveRoot removes a root and everything in it from the folder the walk to it holds,
// following nothing: a junction in it to a folder outside, and one deeper, are removed as junctions,
// and a read-only file is removed with the rest, with what each junction led to untouched. A CONFLUX_DIR whose DACL lets Users add to it,
// which the readers' check refuses, is removed all the same. A root not there is nothing removed.
// Windows-only, so it runs in CI's platforms job alone.
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

	mklinkJ(t, filepath.Join(root, "anchor"), elsewhere)
	mklinkJ(t, filepath.Join(d.Run, "anchord"), elsewhere)

	readOnly := filepath.Join(root, "conflux.json")
	if err := os.WriteFile(readOnly, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(readOnly, 0o400); err != nil {
		t.Fatal(err)
	}

	privtest.GrantUsers(t, root, windows.FILE_WRITE_DATA, windows.NO_INHERITANCE)

	if err := d.Check(); err == nil {
		t.Fatal("Check(a CONFLUX_DIR Users may add to) = nil, want the readers' refusal this is about")
	}

	if gone, err := RemoveRoot(root); !gone || err != nil {
		t.Fatalf("RemoveRoot(%s) = %v, %v, want it removed", root, gone, err)
	}

	if _, err := os.Lstat(root); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s is there once RemoveRoot removed it (%v)", root, err)
	}

	if b, err := os.ReadFile(kept); err != nil || string(b) != "kept" {
		t.Errorf("RemoveRoot reached %s through a junction: %q, %v", kept, b, err)
	}

	for _, absent := range []string{root, filepath.Join(t.TempDir(), "not", "there")} {
		if gone, err := RemoveRoot(absent); gone || err != nil {
			t.Errorf("RemoveRoot(%s, which is not there) = %v, %v, want nothing removed", absent, gone, err)
		}
	}
}

// TestRemoveRootFollowsALinkRootOnlyWhereConfluxWould: a root that is itself a junction -- one moved
// to another volume -- is gone into only where conflux would follow it in daily use, to a folder conflux
// has secured as a root, as it has every working installation's, a platform root's and a CONFLUX_DIR's
// alike: a junction secured as conflux secures one, which nobody but SYSTEM and the Administrators may
// point elsewhere, leading to a folder the Administrators own under a protected DACL granting SYSTEM and
// them alone, is followed, what that folder holds removed through the handle held on it, a junction in
// it as itself, and then the junction, the folder left empty; a junction as mklink made it, which the
// administrator's own processes may repoint unelevated and the SYSTEM service would not follow, to that
// same folder, and a junction secured so to a folder Users may add to, or to one of this account's
// own whose DACL is as it inherited it, neither of which conflux has secured, to one the Guests own,
// and to the folder it is in, under a DACL as conflux secures a root's, are removed as themselves, with
// where each leads left as it was. Windows-only, so it runs in CI's platforms job alone.
func TestRemoveRootFollowsALinkRootOnlyWhereConfluxWould(t *testing.T) {
	elsewhere := t.TempDir()

	kept := filepath.Join(elsewhere, "kept")
	if err := os.WriteFile(kept, []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}

	guests, err := windows.CreateWellKnownSid(windows.WinBuiltinGuestsSid)
	if err != nil {
		t.Fatal(err)
	}

	for _, chosen := range []bool{false, true} {
		secured := func(t *testing.T, target string) {
			privtest.SetSecurity(t, target, "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
		}

		// asMade is a case whose junction is left as mklink made it; every other's is secured as conflux
		// secures one, so that what is judged of where it leads is all that keeps it from being gone into.
		for _, c := range []struct {
			name   string
			target func(t *testing.T, in string) string
			after  func(t *testing.T, target string)
			asMade bool
			follow bool
		}{
			{"a folder conflux secured", func(t *testing.T, _ string) string { return t.TempDir() }, secured, false,
				true},
			{"a folder conflux secured, as mklink made the junction", func(t *testing.T, _ string) string {
				return t.TempDir()
			}, secured, true, false},
			{"a folder Users may add to", func(t *testing.T, _ string) string {
				open := t.TempDir()
				privtest.GrantUsers(t, open, windows.FILE_WRITE_DATA, windows.NO_INHERITANCE)

				return open
			}, nil, false, false},
			{"a folder of this account's own its DACL as inherited", func(t *testing.T, _ string) string {
				return t.TempDir()
			}, nil, false, false},
			{"a folder the Guests own", func(t *testing.T, _ string) string { return t.TempDir() },
				func(t *testing.T, target string) { privtest.SetOwner(t, target, guests) }, false, false},
			{"the folder it is in", func(_ *testing.T, in string) string { return in }, secured, false, false},
		} {
			t.Run(c.name+map[bool]string{true: ", a CONFLUX_DIR"}[chosen], func(t *testing.T) {
				in := t.TempDir()
				root := filepath.Join(in, "conflux")

				t.Setenv("CONFLUX_DIR", "")
				if chosen {
					t.Setenv("CONFLUX_DIR", root)
				}

				target := c.target(t, in)

				if err := os.WriteFile(filepath.Join(target, "manifest.b64"), []byte("identity"), 0o600); err != nil {
					t.Fatal(err)
				}

				mklinkJ(t, filepath.Join(target, "anchor"), elsewhere)

				if c.after != nil {
					c.after(t, target)
				}

				mklinkJ(t, root, target)

				if !c.asMade {
					setOwnSecurity(t, root, "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")
				}

				if gone, err := RemoveRoot(root); !gone || err != nil {
					t.Fatalf("RemoveRoot(a junction at a root's name to %s) = %v, %v, want it removed", c.name, gone, err)
				}

				if _, err := os.Lstat(root); !errors.Is(err, fs.ErrNotExist) {
					t.Errorf("the junction at %s is there once RemoveRoot removed it (%v)", root, err)
				}

				entries, err := os.ReadDir(target)

				switch {
				case err != nil:
					t.Errorf("RemoveRoot of a junction to %s removed where it led: %v", c.name, err)
				case c.follow && len(entries) != 0:
					t.Errorf("RemoveRoot of a junction to %s left %v there, want it emptied", c.name, entries)
				case !c.follow && len(entries) != 2:
					t.Errorf("RemoveRoot of a junction to %s left %v there, want it untouched", c.name, entries)
				}

				if b, err := os.ReadFile(kept); err != nil || string(b) != "kept" {
					t.Errorf("RemoveRoot reached %s through a junction in where a junction at a root's name led: %q, %v",
						kept, b, err)
				}
			})
		}
	}
}

// TestRemoveRootRemovesWhatGrantsTheAdministratorsNothing: what another account planted in a root,
// owning it under a DACL that grants the Administrators nothing, is removed all the same: a file is
// opened to delete it and read its attributes, which the root's own DACL grants, and not to read it,
// as the access it is opened for says, and a folder, which must be listed, is opened with backup
// intent, which the privileges an Administrator holds grant. Windows-only, so it runs in CI's platforms
// job alone.
func TestRemoveRootRemovesWhatGrantsTheAdministratorsNothing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "conflux")
	t.Setenv("CONFLUX_DIR", root)

	if err := Default().EnsureAll(); err != nil {
		t.Fatal(err)
	}

	guests, err := windows.CreateWellKnownSid(windows.WinBuiltinGuestsSid)
	if err != nil {
		t.Fatal(err)
	}

	folder := Default().AnchorDir()
	if err := os.Mkdir(folder, 0o700); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{Default().ConfigFile(), filepath.Join(folder, "inside"), folder} {
		if p != folder {
			if err := os.WriteFile(p, []byte("theirs"), 0o600); err != nil {
				t.Fatal(err)
			}
		}

		privtest.SetSecurity(t, p, "D:P(A;;FA;;;SY)")
		privtest.SetOwner(t, p, guests)
	}

	if gone, err := RemoveRoot(root); !gone || err != nil {
		t.Fatalf("RemoveRoot(a root holding what grants the Administrators nothing) = %v, %v, want it removed", gone, err)
	}

	if _, err := os.Lstat(root); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("%s is there once RemoveRoot removed it (%v)", root, err)
	}

	// Backup intent would grant a read too, so that a file is never opened to be read is what the open
	// asks for, not what it is granted.
	const reads = windows.FILE_READ_DATA | windows.FILE_READ_EA | windows.GENERIC_READ | windows.GENERIC_ALL |
		windows.MAXIMUM_ALLOWED
	if removeAccess&reads != 0 {
		t.Errorf("a file is opened to be removed for %#x, which reads it", removeAccess&reads)
	}
}

// TestRemoveRootHoldsACONFLUXDIRsWay: a CONFLUX_DIR's way is held to parents' rule before anything in
// it is removed, as the readers' check holds it, since a way another account may change could lead the
// removal elsewhere: one inside a folder whose DACL lets Users delete what is in it is refused, naming
// that folder, and left. A platform root's way is not judged, as it is not when the root is made, and
// the root is removed. Windows-only, so it runs in CI's platforms job alone.
func TestRemoveRootHoldsACONFLUXDIRsWay(t *testing.T) {
	open := t.TempDir()
	privtest.GrantUsers(t, open, fileDeleteChild, windows.NO_INHERITANCE)

	root := filepath.Join(open, "conflux")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONFLUX_DIR", root)

	if gone, err := RemoveRoot(root); gone || err == nil || !strings.Contains(err.Error(), open) {
		t.Errorf("RemoveRoot(a CONFLUX_DIR inside a folder Users may delete from) = %v, %v, want a refusal naming it",
			gone, err)
	}

	if _, err := os.Lstat(root); err != nil {
		t.Errorf("RemoveRoot refusing a CONFLUX_DIR's way removed it: %v", err)
	}

	t.Setenv("CONFLUX_DIR", "")

	if gone, err := RemoveRoot(root); !gone || err != nil {
		t.Errorf("RemoveRoot(a platform root inside a folder Users may delete from) = %v, %v, want it removed", gone,
			err)
	}
}

// TestTheWayConfluxMadeIsRemovedWhenEmpty: EnsureAll records each folder it made on the way to an
// installation's CONFLUX_DIR, and Way reads the record back, deepest first. Once the root is gone,
// RemoveWay removes each that is empty, through handles, and leaves one holding anything else and a
// junction put at a recorded folder's name, with where it leads untouched. Windows-only, so it runs in
// CI's platforms job alone.
func TestTheWayConfluxMadeIsRemovedWhenEmpty(t *testing.T) {
	base := t.TempDir()
	a, b := filepath.Join(base, "a"), filepath.Join(base, "a", "b")
	root := filepath.Join(b, "conflux")

	t.Setenv("CONFLUX_DIR", root)
	d := Default()

	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	way, err := d.Way()
	if err != nil || !slices.Equal(way, []string{b, a}) {
		t.Fatalf("Way() = %q, %v, want %q", way, err, []string{b, a})
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

	elsewhere := t.TempDir()
	mklinkJ(t, b, elsewhere)

	if removed, err := RemoveWay(way); err != nil || removed != nil {
		t.Errorf("RemoveWay(%q), a junction at %s = %q, %v, want nothing removed", way, b, removed, err)
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
}

// TestARootIsHeldBeforeAnythingInItIsOpened: what is read in a root before anything has judged it --
// the way record uninstall reads, the serve lock tidy asks after -- is opened through the root held
// (OpenIn), never by its name: a CONFLUX_DIR that is a junction to a folder the Guests own is refused,
// naming the junction, before anything in that folder is opened, though nobody else may point the
// junction elsewhere, and so are one to the folder it is in and one to nothing; one leading to a folder
// of this account's own is followed, and what is in it read, whether nobody else may use it or its DACL
// lets Users add to it, which secure would restrict, as it restricts a root at the name itself.
// Windows-only, so it runs in CI's platforms job alone.
func TestARootIsHeldBeforeAnythingInItIsOpened(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "conflux")
	t.Setenv("CONFLUX_DIR", root)

	d := Default()

	guests, err := windows.CreateWellKnownSid(windows.WinBuiltinGuestsSid)
	if err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		name   string
		target func(t *testing.T) string
		after  func(t *testing.T, target string)
		ok     bool
	}{
		{"a folder nobody else may use", nil, func(*testing.T, string) {}, true},
		{"a folder Users may add to", nil, func(t *testing.T, target string) {
			privtest.GrantUsers(t, target, windows.FILE_WRITE_DATA, windows.NO_INHERITANCE)
		}, true},
		{"a folder the Guests own", nil, func(t *testing.T, target string) { privtest.SetOwner(t, target, guests) },
			false},
		{"the folder it is in", func(*testing.T) string { return base }, func(*testing.T, string) {}, false},
		{"nothing", func(t *testing.T) string { return filepath.Join(t.TempDir(), "missing") }, nil, false},
	} {
		target := t.TempDir()
		if c.target != nil {
			target = c.target(t)
		}

		if c.after != nil {
			for name, body := range map[string]string{wayName: base + "\n", "serve.lock": ""} {
				if err := os.WriteFile(filepath.Join(target, name), []byte(body), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			c.after(t, target)
		}

		mklinkJ(t, root, target)

		// refused reports whether err refuses the junction, naming it and where it leads.
		refused := func(err error) bool {
			return err != nil && strings.Contains(err.Error(), root+" is a ") && strings.Contains(err.Error(), "link to ")
		}

		switch way, err := d.Way(); {
		case c.ok && (err != nil || !slices.Equal(way, []string{base})):
			t.Errorf("Way(), the root a junction to %s = %q, %v, want it read through it", c.name, way, err)
		case !c.ok && !refused(err):
			t.Errorf("Way(), the root a junction to %s = %q, %v, want a refusal naming the junction", c.name, way, err)
		}

		f, err := d.OpenIn(d.ServeLockFile())
		if err == nil {
			f.Close()
		}

		switch {
		case c.ok && err != nil:
			t.Errorf("OpenIn(the serve lock), the root a junction to %s = %v", c.name, err)
		case !c.ok && !refused(err):
			t.Errorf("OpenIn(the serve lock), the root a junction to %s = %v, want a refusal naming the junction",
				c.name, err)
		}

		if err := os.Remove(root); err != nil {
			t.Fatal(err)
		}
	}
}

// TestASharedFolderIsNoRoot: no root conflux fills, restricts or empties may be a folder others keep
// what is theirs in, whoever owns it: a CONFLUX_DIR whose DACL makes it a space other accounts share,
// as %ProgramData%'s does -- Users let add to it and to the folders made in it, CREATOR OWNER passed
// full control -- is refused by EnsureAll, naming why, with its DACL and what it holds as they were, and
// so is a junction to it; RemoveRoot refuses the folder, removing nothing. A junction to it holding
// what is another account's is refused by JudgeWays and RemoveRoot as a foreign root, the junction
// left; one holding nothing else RemoveRoot removes as itself, leaving the folder as it was.
// Windows-only, so it runs in CI's platforms job alone.
func TestASharedFolderIsNoRoot(t *testing.T) {
	shared := filepath.Join(t.TempDir(), "shared")
	if err := os.Mkdir(shared, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(shared, "theirs"), []byte("theirs"), 0o600); err != nil {
		t.Fatal(err)
	}

	privtest.SetSecurity(t, shared, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;CI;0x6;;;BU)(A;OICIIO;FA;;;CO)")

	junction := mklinkJ(t, filepath.Join(t.TempDir(), "conflux"), shared)

	// asFound is the folder's DACL's grantees and the names it holds.
	asFound := func() (int, []string) {
		entries, err := os.ReadDir(shared)
		if err != nil {
			t.Fatal(err)
		}

		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}

		return len(privtest.ReadSecurity(t, shared).Entries), names
	}

	grants, held := asFound()

	for _, root := range []string{shared, junction} {
		t.Setenv("CONFLUX_DIR", root)

		switch err := Default().JudgeWays(); {
		case root == junction && (!errors.Is(err, ErrForeignRoot) || !strings.Contains(err.Error(), "holds theirs")):
			t.Errorf("JudgeWays(a CONFLUX_DIR of a junction to a folder other accounts share) = %v, want a refusal of a "+
				"foreign root naming theirs", err)
		case root == shared && (!errors.Is(err, ErrSharedRoot) || !strings.Contains(err.Error(), "a folder other accounts share")):
			t.Errorf("JudgeWays(a CONFLUX_DIR of a folder other accounts share) = %v, want a refusal of a shared root", err)
		}

		if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), "a folder other accounts share") {
			t.Errorf("EnsureAll(a CONFLUX_DIR of %s, a folder other accounts share) = %v, want a refusal saying so",
				root, err)
		}

		if g, h := asFound(); g != grants || !slices.Equal(h, held) {
			t.Errorf("EnsureAll(a CONFLUX_DIR of %s) left the shared folder %d entries holding %q, want %d holding %q",
				root, g, h, grants, held)
		}
	}

	t.Setenv("CONFLUX_DIR", shared)

	if gone, err := RemoveRoot(shared); gone || err == nil || !strings.Contains(err.Error(), "a folder other accounts share") {
		t.Errorf("RemoveRoot(a folder other accounts share) = %v, %v, want a refusal saying so", gone, err)
	}

	t.Setenv("CONFLUX_DIR", junction)

	if gone, err := RemoveRoot(junction); gone || err == nil || !strings.Contains(err.Error(), "holds theirs") {
		t.Errorf("RemoveRoot(a junction to a folder other accounts share holding another's) = %v, %v, want a refusal "+
			"naming it", gone, err)
	}

	if err := os.Remove(filepath.Join(shared, "theirs")); err != nil {
		t.Fatal(err)
	}

	if gone, err := RemoveRoot(junction); !gone || err != nil {
		t.Errorf("RemoveRoot(a junction to a folder other accounts share holding nothing else) = %v, %v, want the "+
			"junction removed", gone, err)
	}

	if g, h := asFound(); g != grants || len(h) != 0 {
		t.Errorf("RemoveRoot left the shared folder %d entries holding %q, want it as it was", g, h)
	}
}

// TestOpenInReadsThroughTheRootHeld: what OpenIn opens is looked up in the root it holds, and not by its
// name, so a root put at the name once OpenIn holds the one there -- the one held moved aside, another
// made in its place holding a lock of its own -- answers for nothing: what is read is the held root's.
// Windows-only, so it runs in CI's platforms job alone.
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

// TestOpenInHoldsTheRootAndAJunctionToTheirOwners: OpenIn reads nothing in a root at the name that an
// account other than SYSTEM, the Administrators and this one owns -- here the Guests' -- nor through a
// junction there that the Guests own, who could point it at a folder of their own, though it leads to a
// folder of this account's; each refusal names the root and the owner. Windows-only, so it runs in CI's
// platforms job alone.
func TestOpenInHoldsTheRootAndAJunctionToTheirOwners(t *testing.T) {
	guests, err := windows.CreateWellKnownSid(windows.WinBuiltinGuestsSid)
	if err != nil {
		t.Fatal(err)
	}

	root := filepath.Join(t.TempDir(), "conflux")
	t.Setenv("CONFLUX_DIR", root)

	d := Default()

	for name, plant := range map[string]func(t *testing.T){
		"a folder the Guests own": func(t *testing.T) {
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}

			if err := os.WriteFile(d.ServeLockFile(), nil, 0o600); err != nil {
				t.Fatal(err)
			}

			privtest.SetOwner(t, root, guests)
		},
		"a junction the Guests own": func(t *testing.T) {
			target := t.TempDir()
			if err := os.WriteFile(filepath.Join(target, "serve.lock"), nil, 0o600); err != nil {
				t.Fatal(err)
			}

			mklinkJ(t, root, target)

			if err := privtest.WithRestore(t, func() error {
				setOwnSecurity(t, root, "O:BGD:P(A;;FA;;;SY)(A;;FA;;;BA)")

				return nil
			}); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			plant(t)
			t.Cleanup(func() { os.RemoveAll(root) })

			f, err := d.OpenIn(d.ServeLockFile())
			if err == nil {
				f.Close()
			}

			if err == nil || !strings.Contains(err.Error(), root) || !strings.Contains(err.Error(), guests.String()) {
				t.Errorf("OpenIn(the serve lock), the root %s = %v, want a refusal naming it and its owner", name, err)
			}
		})
	}
}

// TestRemoveKilledRunEmptiesOnlyARootConfluxSecured: what a killed ephemeral run left in its root is
// removed through the root held, the run's lock kept, and named, a junction in it removed as itself with
// where it led untouched; and the folder a junction at the root's name leads to is emptied where conflux
// secured both, as secure leaves a junction it made its own. A junction as mklink made it -- one the
// administrator's own processes may point elsewhere unelevated, here at a folder of SYSTEM's and the
// Administrators' holding an identity, as an installation's root does -- is refused (ErrUnsecuredRoot), and so is a root whose DACL as inherited grants more
// than conflux leaves, each with nothing removed. Windows-only, so it runs in CI's platforms job alone.
func TestRemoveKilledRunEmptiesOnlyARootConfluxSecured(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	elsewhere := t.TempDir()

	kept := filepath.Join(elsewhere, "kept")
	if err := os.WriteFile(kept, []byte("kept"), 0o600); err != nil {
		t.Fatal(err)
	}

	// killed is a root an ephemeral run's EnsureAll made, holding a killed run's lock and token, and a
	// junction to elsewhere.
	killed := func(root string) Dirs {
		e := EphemeralDirs(root)
		if err := e.EnsureAll(); err != nil {
			t.Fatal(err)
		}

		for _, p := range []string{e.ServeLockFile(), e.TokenFile()} {
			if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}

		mklinkJ(t, e.DaemonRun(), elsewhere)

		return e
	}

	names := func(t *testing.T, dir string) []string {
		t.Helper()

		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}

		var held []string
		for _, e := range entries {
			held = append(held, e.Name())
		}

		return held
	}

	root := filepath.Join(t.TempDir(), "conflux-ephemeral")
	e := killed(root)

	if err := JudgeKilledRun(root); err != nil {
		t.Errorf("JudgeKilledRun(a killed run's root) = %v", err)
	}

	if removed, err := RemoveKilledRun(root, e.ServeLockFile()); err != nil || !slices.Equal(removed, []string{e.Run}) {
		t.Errorf("RemoveKilledRun(a killed run's root) = %q, %v, want %q", removed, err, []string{e.Run})
	}

	if held := names(t, root); !slices.Equal(held, []string{"serve.lock"}) {
		t.Errorf("RemoveKilledRun left the root holding %q, want its lock alone", held)
	}

	if b, err := os.ReadFile(kept); err != nil || string(b) != "kept" {
		t.Errorf("RemoveKilledRun reached %s through a junction: %q, %v", kept, b, err)
	}

	target := filepath.Join(t.TempDir(), "moved")
	killed(target)

	secured := filepath.Join(t.TempDir(), "conflux-ephemeral")
	mklinkJ(t, secured, target)
	setOwnSecurity(t, secured, "O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)")

	if _, err := RemoveKilledRun(secured, EphemeralDirs(secured).ServeLockFile()); err != nil {
		t.Errorf("RemoveKilledRun(a junction conflux secured to a killed run's root) = %v", err)
	}

	if held := names(t, target); !slices.Equal(held, []string{"serve.lock"}) {
		t.Errorf("RemoveKilledRun left where the junction leads holding %q, want its lock alone", held)
	}

	// An installation's root, say, which holds nothing but what conflux makes there.
	theirs := t.TempDir()
	if err := os.WriteFile(filepath.Join(theirs, "manifest.b64"), []byte("identity"), 0o600); err != nil {
		t.Fatal(err)
	}

	privtest.SetSecurity(t, theirs, "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")

	asMade := mklinkJ(t, filepath.Join(t.TempDir(), "conflux-ephemeral"), theirs)

	inherited := filepath.Join(t.TempDir(), "conflux-ephemeral")
	if err := os.Mkdir(inherited, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(inherited, "serve.lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	for name, c := range map[string]struct{ root, holds string }{
		"a junction as mklink made it, to a folder of SYSTEM's and the Administrators'": {asMade, theirs},
		"a root whose DACL is as it inherited it":                                       {inherited, inherited},
	} {
		t.Run(name, func(t *testing.T) {
			was := names(t, c.holds)

			if err := JudgeKilledRun(c.root); !errors.Is(err, ErrUnsecuredRoot) || !strings.Contains(err.Error(), c.root) {
				t.Errorf("JudgeKilledRun(%s) = %v, want a refusal that is ErrUnsecuredRoot naming it", name, err)
			}

			removed, err := RemoveKilledRun(c.root, EphemeralDirs(c.root).ServeLockFile())
			if len(removed) > 0 || !errors.Is(err, ErrUnsecuredRoot) || !strings.Contains(err.Error(), c.root) {
				t.Errorf("RemoveKilledRun(%s) = %q, %v, want a refusal that is ErrUnsecuredRoot naming it", name,
					removed, err)
			}

			if held := names(t, c.holds); !slices.Equal(held, was) {
				t.Errorf("RemoveKilledRun(%s) left %s holding %q, want %q", name, c.holds, held, was)
			}
		})
	}
}

// TestARootConfluxCannotLookUpIsRefused: a root whose name conflux cannot open in the folder it is in --
// a folder the Guests own whose DACL grants SYSTEM alone, which denies the Administrators the right to read
// who owns it -- is not judged, so uninstall's pre-flight (JudgeWays) refuses it, as none of its kinds,
// and RemoveRoot refuses it and removes nothing, though its backup intent could have removed it all.
// Windows-only, so it runs in CI's platforms job alone.
func TestARootConfluxCannotLookUpIsRefused(t *testing.T) {
	root := filepath.Join(t.TempDir(), "conflux")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(root, "manifest.b64"), []byte("identity"), 0o600); err != nil {
		t.Fatal(err)
	}

	guests, err := windows.CreateWellKnownSid(windows.WinBuiltinGuestsSid)
	if err != nil {
		t.Fatal(err)
	}

	privtest.SetSecurity(t, root, "D:P(A;OICI;FA;;;SY)")
	privtest.SetOwner(t, root, guests)

	t.Cleanup(func() {
		privtest.SetOwner(t, root, privtest.Admins)
		privtest.SetSecurity(t, root, "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	})

	t.Setenv("CONFLUX_DIR", root)

	switch err := Default().JudgeWays(); {
	case err == nil:
		t.Errorf("JudgeWays(a CONFLUX_DIR conflux cannot look up) = nil, want a refusal")
	case errors.Is(err, ErrWayRefused), errors.Is(err, ErrSharedRoot), errors.Is(err, ErrForeignRoot):
		t.Errorf("JudgeWays(a CONFLUX_DIR conflux cannot look up) = %v, want a refusal of none of its kinds", err)
	}

	if gone, err := RemoveRoot(root); gone || err == nil {
		t.Errorf("RemoveRoot(a root conflux cannot look up) = %v, %v, want a refusal, nothing removed", gone, err)
	}

	if _, err := os.Lstat(root); err != nil {
		t.Errorf("RemoveRoot removed a root conflux cannot look up: %v", err)
	}
}
