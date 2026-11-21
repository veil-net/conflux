package paths

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/privtest"
	"golang.org/x/sys/windows"
)

// These tests make what they make the Administrators', as every conflux process does as it starts
// (ElevatedDefaultOwner), and root it on a way the boot service trusts (privtest.ServiceTemp), since
// EnsureAll holds an installation's way to the rule SYSTEM holds it to, which the profile of the
// administrator running them, where %TEMP% is, does not pass.
func init() {
	if err := ElevatedDefaultOwner(); err != nil {
		panic("paths: " + err.Error())
	}

	if err := privtest.ServiceTemp(); err != nil {
		panic("paths: " + err.Error())
	}
}

// TestEnsureAllGivesTheRootToAdministrators: the root is made SYSTEM's and Administrators', owned
// by the Administrators, with a DACL %ProgramData%'s grants to Users cannot flow back into, and what
// is created beneath it afterwards inherits that and is the Administrators' too. Windows-only, so it
// runs in CI's platforms job alone.
func TestEnsureAllGivesTheRootToAdministrators(t *testing.T) {
	root := filepath.Join(t.TempDir(), "conflux")
	t.Setenv("CONFLUX_DIR", root)

	d := Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatalf("EnsureAll: %v", err)
	}

	onlyTheSystems(t, d.State)

	// Idempotent: a second call finds it already done.
	if err := d.EnsureAll(); err != nil {
		t.Fatalf("EnsureAll again: %v", err)
	}

	f := filepath.Join(d.Run, "token")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, p := range []string{d.State, d.Run, f} {
		if owner := privtest.ReadSecurity(t, p).Owner; !owner.Equals(sidAdmins) {
			t.Errorf("%s belongs to %v, want the Administrators", p, owner)
		}
	}
}

func TestRestrictedFilesAreTrusted(t *testing.T) {
	f := filepath.Join(t.TempDir(), "anchord.exe")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Restrict(f, false); err != nil {
		t.Fatalf("Restrict: %v", err)
	}

	if !Trusted(f) {
		t.Error("a file Restrict has just made Administrators' is not trusted")
	}
}

// TestEnsureAllRefusesARootAnotherAccountCanMove: an account granted the right to delete or
// rename what is in a directory above a CONFLUX_DIR can move the root aside and put one of
// its own in its place, with a conflux in it for the service to run as SYSTEM, so the root
// is refused, naming the directory, and before anything is made in it -- the root, or a directory
// on the way to it -- where that account could have made a junction for MkdirAll and makeRoot to
// follow. The right to create folders there is not that: C:\ gives it to every user, and their
// folder cannot take the place of one that is not theirs. Windows-only, so it runs in CI's
// platforms job alone.
func TestEnsureAllRefusesARootAnotherAccountCanMove(t *testing.T) {
	for _, c := range []struct {
		name    string
		access  windows.ACCESS_MASK
		refused bool
	}{
		{"Users may rename what is in it", fileDeleteChild, true},
		{"Users may create folders in it", 0x4, false}, // FILE_ADD_SUBDIRECTORY
	} {
		for _, under := range []string{"conflux", filepath.Join("made", "conflux")} {
			t.Run(c.name+", "+under, func(t *testing.T) {
				parent := t.TempDir()
				privtest.GrantUsers(t, parent, c.access, windows.NO_INHERITANCE)

				t.Setenv("CONFLUX_DIR", filepath.Join(parent, under))

				err := Default().EnsureAll()

				switch {
				case c.refused && (err == nil || !strings.Contains(err.Error(), parent)):
					t.Errorf("a root in %s was accepted, or the refusal does not name it: %v", parent, err)
				case !c.refused && err != nil:
					t.Errorf("a root in %s was refused: %v", parent, err)
				}

				first := filepath.Join(parent, strings.Split(under, string(filepath.Separator))[0])
				if _, err := os.Lstat(first); c.refused && !errors.Is(err, os.ErrNotExist) {
					t.Errorf("EnsureAll made %s in a directory it refused (%v)", first, err)
				}
			})
		}
	}
}

// grantLink gives Users access to link, a link or junction, beside what its DACL grants already: its
// own DACL, opened as itself, where privtest.GrantUsers's named calls would follow it and change the
// DACL of where it leads.
func grantLink(t *testing.T, link string, access windows.ACCESS_MASK) {
	t.Helper()

	name, err := windows.UTF16PtrFromString(link)
	if err != nil {
		t.Fatal(err)
	}

	h, err := windows.CreateFile(name, windows.READ_CONTROL|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(h)

	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}

	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION,
		nil, nil, privtest.WithUsers(t, dacl, access, windows.NO_INHERITANCE), nil); err != nil {
		t.Fatal(err)
	}
}

// TestEnsureAllFollowsAJunction: a junction is a link the lookup follows, which Go does not
// report as one, so a root that is a junction, or that one leads to, is held to the
// directories above where it leads too -- here one Users may rename what is in -- and a
// junction on the way is followed rather than taken for a file. A junction is held as well to
// who may point it elsewhere: here Users, granted the right to write its attributes, which
// is enough to rewrite its target, though where it leads is nobody else's.
func TestEnsureAllFollowsAJunction(t *testing.T) {
	open := filepath.Join(t.TempDir(), "open-to-users")
	if err := os.MkdirAll(filepath.Join(open, "real"), 0o700); err != nil {
		t.Fatal(err)
	}

	privtest.GrantUsers(t, open, fileDeleteChild, windows.NO_INHERITANCE)

	junction := mklinkJ(t, filepath.Join(t.TempDir(), "j"), filepath.Join(open, "real"))

	for _, root := range []string{junction, filepath.Join(junction, "conflux")} {
		t.Setenv("CONFLUX_DIR", root)

		if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), "open-to-users") {
			t.Errorf("a root at %s, through a junction into a directory Users may rename what is in, was accepted, "+
				"or the refusal does not name that directory: %v", root, err)
		}
	}

	retargeted := mklinkJ(t, filepath.Join(t.TempDir(), "j"), t.TempDir())
	grantLink(t, retargeted, windows.FILE_WRITE_ATTRIBUTES)

	root := filepath.Join(retargeted, "conflux")
	t.Setenv("CONFLUX_DIR", root)

	if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), retargeted) {
		t.Errorf("a root at %s, through a junction Users may point elsewhere, was accepted, or the refusal does not "+
			"name the junction: %v", root, err)
	}
}

// mklinkJ makes a junction at link that leads to target, and is link.
func mklinkJ(t *testing.T, link, target string) string {
	t.Helper()

	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v\n%s", err, out)
	}

	return link
}

// TestEnsureAllRemakesWhatIsNotItsOwn: what is at the root's name and is not as conflux makes a root
// is refused by the readers' check, naming it, and removed as itself by EnsureAll, which makes the root
// afresh, SYSTEM's and the Administrators' alone: a junction, where it leads never touched, though it
// is a folder of this account's; a folder granting Users the right to read it; one the Guests own, as
// %ProgramData% lets any account make a folder at a name not taken yet; and one that grants this
// administrator full control, which the SYSTEM service does not trust. What any of them held goes with
// it. Windows-only, so it runs in CI's platforms job alone.
func TestEnsureAllRemakesWhatIsNotItsOwn(t *testing.T) {
	elsewhere := t.TempDir()

	kept := filepath.Join(elsewhere, "kept")
	if err := os.WriteFile(kept, []byte("not conflux's"), 0o600); err != nil {
		t.Fatal(err)
	}

	guests := wellKnown(windows.WinBuiltinGuestsSid)

	for name, plant := range map[string]func(t *testing.T, root string){
		"a junction": func(t *testing.T, root string) { mklinkJ(t, root, elsewhere) },
		"a folder Users may read": func(t *testing.T, root string) {
			grantedFolder(t, root, windows.FILE_READ_DATA)
		},
		"a folder the Guests own": func(t *testing.T, root string) {
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}

			privtest.SetOwner(t, root, guests)
		},
		"a folder granting this administrator": func(t *testing.T, root string) {
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}

			privtest.Grant(t, root, currentUser(), fileAllAccess, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
		},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv("CONFLUX_DIR", t.TempDir())

			d := Default()
			plant(t, d.State)

			if name != "a junction" {
				if err := os.WriteFile(filepath.Join(d.State, "planted"), []byte("somebody's"), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			if err := d.Check(); err == nil || !strings.Contains(err.Error(), d.State+" is not as conflux makes") {
				t.Errorf("Check(%s at the root's name) = %v, want a refusal naming it", name, err)
			}

			if err := d.EnsureAll(); err != nil {
				t.Fatalf("EnsureAll(%s at the root's name) = %v", name, err)
			}

			onlyTheSystems(t, d.State)

			if fi, err := os.Lstat(d.State); err != nil || fi.Mode()&os.ModeIrregular != 0 || !fi.IsDir() {
				t.Errorf("the root is %v (%v), want a folder", fi, err)
			}

			if _, err := os.Lstat(filepath.Join(d.State, "planted")); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("the root made afresh holds what was planted (Lstat: %v)", err)
			}

			if b, err := os.ReadFile(kept); err != nil || string(b) != "not conflux's" {
				t.Errorf("where a junction at the root's name led lost what is in it: %q, %v", b, err)
			}

			if err := d.Check(); err != nil {
				t.Errorf("Check(the root EnsureAll made afresh) = %v", err)
			}
		})
	}
}

// TestEnsureAllRemakesAFolderOfItsOwnNotAsConfluxMakesIt: each folder conflux keeps in an installation's
// root -- run\, logs\, bin\ and anchor.root\ -- is judged as the root is, for the SYSTEM service, and one
// not as conflux makes it is removed as itself, whatever it held, and made afresh, SYSTEM's and the
// Administrators' alone: a junction, where it leads never touched; a folder granting Users the right to
// read it; and one this administrator owns, as an earlier conflux left bin\, run\ and logs\ on a Windows
// client, whose unelevated processes could change it. Windows-only, so it runs in CI's platforms job
// alone.
func TestEnsureAllRemakesAFolderOfItsOwnNotAsConfluxMakesIt(t *testing.T) {
	elsewhere := t.TempDir()

	kept := filepath.Join(elsewhere, "kept")
	if err := os.WriteFile(kept, []byte("not conflux's"), 0o600); err != nil {
		t.Fatal(err)
	}

	plants := map[string]func(t *testing.T, dir string){
		"a junction": func(t *testing.T, dir string) { mklinkJ(t, dir, elsewhere) },
		"a folder Users may read": func(t *testing.T, dir string) {
			grantedFolder(t, dir, windows.FILE_READ_DATA)
		},
		"a folder this administrator owns": func(t *testing.T, dir string) {
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}

			privtest.SetOwner(t, dir, currentUser())
		},
	}

	t.Setenv("CONFLUX_DIR", t.TempDir())

	d := Default()

	for _, dir := range []string{d.Run, d.Log, d.Libexec(), d.RootAnchorDir()} {
		for name, plant := range plants {
			t.Run(filepath.Base(dir)+"/"+name, func(t *testing.T) {
				if err := d.EnsureAll(); err != nil {
					t.Fatal(err)
				}

				if err := os.RemoveAll(dir); err != nil {
					t.Fatal(err)
				}

				plant(t, dir)

				if name != "a junction" {
					if err := os.WriteFile(filepath.Join(dir, "planted"), []byte("somebody's"), 0o600); err != nil {
						t.Fatal(err)
					}
				}

				if err := d.EnsureAll(); err != nil {
					t.Fatalf("EnsureAll(%s at %s) = %v", name, dir, err)
				}

				onlyTheSystems(t, dir)

				if fi, err := os.Lstat(dir); err != nil || fi.Mode()&os.ModeIrregular != 0 || !fi.IsDir() {
					t.Errorf("%s is %v (%v), want a folder", dir, fi, err)
				}

				if _, err := os.Lstat(filepath.Join(dir, "planted")); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("%s made afresh holds what was planted (Lstat: %v)", dir, err)
				}

				if b, err := os.ReadFile(kept); err != nil || string(b) != "not conflux's" {
					t.Errorf("where a junction at %s led lost what is in it: %q, %v", dir, b, err)
				}
			})
		}
	}
}

// TestEnsureAllLeavesTheConfluxDirAsItWas: a CONFLUX_DIR that is a folder of the user's, holding
// files of theirs and granting Users the right to read it, is never changed: conflux keeps everything
// in .conflux inside it, made SYSTEM's and the Administrators' alone, and the folder keeps its own
// owner and DACL and what it held. Windows-only, so it runs in CI's platforms job alone.
func TestEnsureAllLeavesTheConfluxDirAsItWas(t *testing.T) {
	home := t.TempDir()
	privtest.GrantUsers(t, home, windows.FILE_READ_DATA, windows.NO_INHERITANCE)

	notes := filepath.Join(home, "notes.txt")
	if err := os.WriteFile(notes, []byte("the user's"), 0o600); err != nil {
		t.Fatal(err)
	}

	before := privtest.ReadSecurity(t, home)

	t.Setenv("CONFLUX_DIR", home)

	d := Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatalf("EnsureAll(a CONFLUX_DIR of the user's) = %v", err)
	}

	onlyTheSystems(t, d.State)

	after := privtest.ReadSecurity(t, home)
	if !after.Owner.Equals(before.Owner) || after.Protected != before.Protected ||
		len(after.Entries) != len(before.Entries) {
		t.Errorf("the CONFLUX_DIR's owner and DACL changed: %+v, was %+v", after, before)
	}

	if b, err := os.ReadFile(notes); err != nil || string(b) != "the user's" {
		t.Errorf("%s changed: %q, %v", notes, b, err)
	}
}

// TestARootOnANetworkVolumeIsRefused: who owns what a network volume holds, and whom its DACLs
// grant, are the accounts of the machine serving it, which this one cannot judge, so a root on
// one is refused by EnsureAll and by the readers' check alike, naming the network volume, as the
// device the top of its volume is open on says and not as it is spelled: reached by its UNC path, or
// through a drive mapped to the share. Nothing is made there. A link to that drive at the root's name
// is no root of conflux's: the readers' check refuses it, and EnsureAll removes it as itself, and
// makes the root here, nothing made on the share. A link naming the share itself, on the way to a
// CONFLUX_DIR, is refused as a link before anything follows it (and further in
// TestALinkLeadingOffThisMachineOrNowhereIsRefused). The share is a folder of this machine's, reached
// through its own server. Windows-only, so it runs in CI's platforms job alone, and skipped where the
// machine will not share a folder.
func TestARootOnANetworkVolumeIsRefused(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	root := foundRoot(t)
	dir := filepath.Dir(root)

	share := privtest.Share(t, dir)
	unc := filepath.Join(share, "conflux")

	drive := privtest.MapDrive(t, share)

	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(filepath.Join(drive, "conflux"), link); err != nil {
		t.Fatal(err)
	}

	at := func(root string) Dirs { return Dirs{Config: root, State: root, Run: filepath.Join(root, runName)} }

	for _, root := range []string{unc, filepath.Join(drive, "conflux")} {
		for name, judge := range map[string]func() error{"Check": at(root).Check, "EnsureAll": at(root).EnsureAll} {
			if err := judge(); err == nil || !strings.Contains(err.Error(), " is on a network volume") {
				t.Errorf("%s(%s) = %v, want a refusal naming the network volume", name, root, err)
			}
		}
	}

	if err := at(link).Check(); err == nil || !strings.Contains(err.Error(), link+" is not as conflux makes") {
		t.Errorf("Check(a link at the root's name to a network volume) = %v, want a refusal naming it", err)
	}

	if err := at(link).EnsureAll(); err != nil {
		t.Errorf("EnsureAll(a link at the root's name to a network volume) = %v, want it made afresh here", err)
	}

	onlyTheSystems(t, link)

	if _, err := os.Lstat(filepath.Join(dir, "conflux", runName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("EnsureAll made %s in a root on a network volume (%v)", runName, err)
	}

	for _, root := range []string{filepath.Join(share, "made", "conflux"), filepath.Join(drive, "made", "conflux")} {
		t.Setenv("CONFLUX_DIR", root)

		if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), root) ||
			!strings.Contains(err.Error(), " is on a network volume") {
			t.Errorf("EnsureAll(a CONFLUX_DIR of %s) = %v, want a refusal naming it and the network volume", root, err)
		}
	}

	// A link naming the share itself, on the way to a CONFLUX_DIR, is refused as a link before
	// anything is looked up through it (walk), and not as the network volume it leads to.
	toShare := dirSymlink(t, filepath.Join(t.TempDir(), "share"), share)
	made := filepath.Join(toShare, "conflux", "made")
	t.Setenv("CONFLUX_DIR", made)

	if err := Default().EnsureAll(); err == nil ||
		!strings.Contains(err.Error(), "resolve "+made+": "+toShare+" is a link conflux cannot follow") ||
		!strings.Contains(err.Error(), "another machine") {
		t.Errorf("EnsureAll(a CONFLUX_DIR of %s) = %v, want a refusal naming the link %s and another machine", made,
			err, toShare)
	}

	if _, err := os.Lstat(filepath.Join(dir, "made")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("EnsureAll made the way to a CONFLUX_DIR on a network volume it refused (%v)", err)
	}
}

// TestALinkLeadingOffThisMachineOrNowhereIsRefused: a link on the way to a CONFLUX_DIR that names a
// share is read for where it leads off the link itself, and refused before anything follows it, which
// would sign this machine in to whoever serves the share: by EnsureAll and the readers' check alike,
// as a link on the way (walk), before either looks anything up there. The share is 192.0.2.1's,
// TEST-NET-1, which nothing answers: a lookup that followed the link would fail slowly, saying the
// network path was not found, not as these refusals say. A link leading to nothing is refused too, as
// a link conflux cannot follow rather than as a root that is not there, and nothing is made where it
// leads. Either link at a root's own name is no root of conflux's, and is never followed: the readers'
// check refuses it, and EnsureAll removes it as itself and makes the root afresh. Windows-only, so it
// runs in CI's platforms job alone.
func TestALinkLeadingOffThisMachineOrNowhereIsRefused(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	const unc = `\\192.0.2.1\share\conflux`

	nowhere := filepath.Join(t.TempDir(), "nowhere")

	for _, target := range []string{unc, nowhere} {
		root := dirSymlink(t, filepath.Join(t.TempDir(), "conflux"), target)
		d := Dirs{Config: root, State: root, Run: filepath.Join(root, runName)}

		if err := d.Check(); err == nil || !strings.Contains(err.Error(), root+" is not as conflux makes") {
			t.Errorf("Check(a link at the root's name to %s) = %v, want a refusal naming it", target, err)
		}

		if err := d.EnsureAll(); err != nil {
			t.Errorf("EnsureAll(a link at the root's name to %s) = %v, want it made afresh", target, err)
		}

		onlyTheSystems(t, root)
	}

	away := dirSymlink(t, filepath.Join(t.TempDir(), "conflux"), unc)
	dangling := dirSymlink(t, filepath.Join(t.TempDir(), "conflux"), nowhere)

	refusal := func(dir string) string { return "resolve " + dir + ": " + away + " is a link conflux cannot follow" }

	for _, dir := range []string{away, filepath.Join(away, "conflux")} {
		t.Setenv("CONFLUX_DIR", dir)

		root := Default().State

		if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), refusal(dir)) ||
			!strings.Contains(err.Error(), "may be on another machine") {
			t.Errorf("EnsureAll(a CONFLUX_DIR of %s) = %v, want %q, saying it may be on another machine", dir, err,
				refusal(dir))
		}

		for _, d := range []Dirs{Default(), EphemeralDirs(filepath.Join(root, "ephemeral"))} {
			if err := d.Check(); err == nil || !strings.Contains(err.Error(), refusal(filepath.Dir(d.State))) ||
				!strings.Contains(err.Error(), "may be on another machine") {
				t.Errorf("Check(%s), CONFLUX_DIR %s, = %v, want %q, saying it may be on another machine", d.State, dir,
					err, refusal(filepath.Dir(d.State)))
			}
		}
	}

	for _, dir := range []string{dangling, filepath.Join(dangling, "conflux")} {
		t.Setenv("CONFLUX_DIR", dir)

		if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), dangling+" is a link conflux cannot follow") {
			t.Errorf("EnsureAll(a CONFLUX_DIR of %s) = %v, want a refusal naming the link to nothing", dir, err)
		}
	}

	if _, err := os.Lstat(nowhere); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("EnsureAll made %s, where a link it refused leads (%v)", nowhere, err)
	}
}

// dirSymlink makes a directory symbolic link at link naming target, and is link. The target is not
// looked at: os.Symlink stats it to learn whether it is a directory, which for a share reaches for it.
func dirSymlink(t *testing.T, link, target string) string {
	t.Helper()

	l, err := windows.UTF16PtrFromString(link)
	if err != nil {
		t.Fatal(err)
	}

	to, err := windows.UTF16PtrFromString(target)
	if err != nil {
		t.Fatal(err)
	}

	if err := windows.CreateSymbolicLink(l, to, windows.SYMBOLIC_LINK_FLAG_DIRECTORY); err != nil {
		t.Fatalf("make a link at %s to %s: %v", link, target, err)
	}

	return link
}

// TestARootIsMadeWithItsDACL: %ProgramData% passes Users the right to create in what is made in it,
// enough to turn an empty directory into a junction, so a root is made with its own ownership and
// protected DACL set as it is created, and carries that grant not even for an instant: read as
// makeRoot leaves it, before anything else is done, and again once EnsureAll has made one. The
// parent also passes on a denial of WRITE_DAC to whoever owns what is made in it, so a root made
// and then given its DACL would be refused that, and one made with its descriptor never carries
// the entry. One already there as conflux makes one is left as it is. Windows-only, so it runs in
// CI's platforms job alone.
func TestARootIsMadeWithItsDACL(t *testing.T) {
	parent := t.TempDir()

	privtest.ProgramDataGrant(t, parent)
	privtest.DenyOwnersTheirDACL(t, parent)

	made := filepath.Join(parent, "made")
	if _, err := EphemeralDirs(made).makeRoot(made); err != nil {
		t.Fatalf("makeRoot: %v", err)
	}

	onlyTheSystems(t, made)

	if _, err := EphemeralDirs(made).makeRoot(made); err != nil {
		t.Errorf("makeRoot of a root already there: %v", err)
	}

	t.Setenv("CONFLUX_DIR", filepath.Join(parent, "conflux"))

	if err := Default().EnsureAll(); err != nil {
		t.Fatalf("EnsureAll: %v", err)
	}

	onlyTheSystems(t, Default().State)
}

// TestTheWayConfluxMakesIsItsOwn: the folders conflux makes on the way to a CONFLUX_DIR are made
// exactly as the root is, theirs from the moment they exist -- the Administrators', under a protected
// DACL granting SYSTEM and the Administrators full control, passed on to all they hold, and nobody
// else anything -- rather than with what the folder above passes on, which in C:\ lets Authenticated
// Users delete them, and owned by whichever administrator ran conflux, whom the SYSTEM service does
// not trust. So x, y and the CONFLUX_DIR, made for <temp>\x\y\conflux, pass parents' rule for the
// service, SYSTEM, as for the account that made them, and y, taken as a root itself, passes the
// readers' check. Windows-only, so it runs in CI's platforms job alone.
func TestTheWayConfluxMakesIsItsOwn(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "x", "y", "conflux")
	t.Setenv("CONFLUX_DIR", root)

	if err := Default().EnsureAll(); err != nil {
		t.Fatalf("EnsureAll: %v", err)
	}

	way := []string{filepath.Join(base, "x"), filepath.Join(base, "x", "y"), root}

	for _, dir := range way {
		s := privtest.ReadSecurity(t, dir)

		if !s.Owner.Equals(sidAdmins) || !s.Protected {
			t.Errorf("%s belongs to %v, its DACL protected %v; want the Administrators', protected", dir, s.Owner,
				s.Protected)
		}

		const passedOn = windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE

		if len(s.Entries) != 2 {
			t.Errorf("the DACL of %s holds %d entries, want SYSTEM's and the Administrators': %+v", dir, len(s.Entries),
				s.Entries)
		}

		for _, e := range s.Entries {
			if e.Type != windows.ACCESS_ALLOWED_ACE_TYPE || e.Flags != passedOn || e.Mask != fileAllAccess ||
				!e.SID.Equals(sidSystem) && !e.SID.Equals(sidAdmins) {
				t.Errorf("the DACL of %s grants %s %#x, flags %#x, type %d; want SYSTEM and the Administrators "+
					"full control, passed on", dir, e.SID, e.Mask, e.Flags, e.Type)
			}
		}
	}

	if err := EphemeralDirs(way[1]).Check(); err != nil {
		t.Errorf("Check(%s, which conflux made on the way to %s) = %v", way[1], root, err)
	}

	was := currentUser
	t.Cleanup(func() { currentUser = was })

	currentUser = func() *windows.SID { return sidSystem }

	for _, dir := range way {
		name, err := windows.UTF16PtrFromString(dir)
		if err != nil {
			t.Fatal(err)
		}

		h, err := windows.CreateFile(name, readAccess, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING,
			windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
		if err != nil {
			t.Fatal(err)
		}

		if err := parentsRule(root)(dir, step{h}, false); err != nil {
			t.Errorf("parents' rule, for SYSTEM, of %s, which conflux made on the way to %s = %v", dir, root, err)
		}

		windows.CloseHandle(h)
	}
}

// TestAnInstallationsWayIsJudgedAsTheServiceJudgesIt: the boot service runs as SYSTEM, and holds the
// way to its root, at every start, to parents' rule for SYSTEM, which trusts no other account; so
// EnsureAll holds an installation's way to that rule, whoever runs it. A CONFLUX_DIR inside a folder
// granting this account full control, as the profile of the administrator running conflux does, is
// refused, naming the folder and the service, with nothing made in it, though this account's own
// rule takes it; an ephemeral run's root inside that CONFLUX_DIR, which no service serves, is made
// there, and passes the readers' check, which judges for the account reading. Windows-only, so it
// runs in CI's platforms job alone.
func TestAnInstallationsWayIsJudgedAsTheServiceJudgesIt(t *testing.T) {
	profile := filepath.Join(t.TempDir(), "profile")
	if err := os.Mkdir(profile, 0o700); err != nil {
		t.Fatal(err)
	}

	privtest.Grant(t, profile, currentUser(), fileAllAccess, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)

	root := filepath.Join(profile, "conflux")
	t.Setenv("CONFLUX_DIR", root)

	if err := Default().EnsureAll(); err == nil ||
		!strings.Contains(err.Error(), Default().State+" is inside "+profile+", which grants ") ||
		!strings.Contains(err.Error(), "the boot service runs as SYSTEM") {
		t.Errorf("EnsureAll(an installation inside a folder granting this account full control) = %v, want a refusal "+
			"naming the folder and the service", err)
	}

	if _, err := os.Lstat(root); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("EnsureAll made %s on a way it refused (%v)", root, err)
	}

	d, err := Ephemeral()
	if err != nil {
		t.Fatal(err)
	}

	if err := d.EnsureAll(); err != nil {
		t.Errorf("EnsureAll(an ephemeral run's root inside %s) = %v", root, err)
	}

	if err := d.Check(); err != nil {
		t.Errorf("Check(an ephemeral run's root EnsureAll made inside %s) = %v", root, err)
	}
}

// onlyTheSystems fails t unless dir belongs to SYSTEM, the Administrators or this account, under a
// protected DACL whose every entry is SYSTEM's or the Administrators'.
func onlyTheSystems(t *testing.T, dir string) {
	t.Helper()

	s := privtest.ReadSecurity(t, dir)

	if !trusted(s.Owner) {
		t.Errorf("%s belongs to %v", dir, s.Owner)
	}

	if !s.Protected {
		t.Errorf("the DACL of %s is not protected, so %s's grants flow into it", dir, filepath.Dir(dir))
	}

	for _, e := range s.Entries {
		if !e.SID.Equals(sidSystem) && !e.SID.Equals(sidAdmins) {
			t.Errorf("the DACL of %s grants %s", dir, e.SID)
		}
	}
}

// grantedFolder is the folder dir, made and granted access for Users.
func grantedFolder(t *testing.T, dir string, access windows.ACCESS_MASK) string {
	t.Helper()

	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	privtest.GrantUsers(t, dir, access, windows.NO_INHERITANCE)

	return dir
}

// TestAReaderRefusesARootItCannotRead: %ProgramData% lets any account make conflux-ephemeral where
// no run has made it yet, and give it a DACL denying everybody the right to read it, so only a root
// that is not there, or under a directory that is not, is taken by the readers' check for none,
// fs.ErrNotExist, unread: one this account may not open is refused, naming it and the denial, rather
// than taken for a run's or for none; and EnsureAll, which may remove it whatever its DACL says, makes
// the root afresh. Owned by the Guests, a group this process's token does not hold: an owner is let
// read a DACL whatever the DACL says, and an Administrator's token holds Users. Windows-only, so it
// runs in CI's platforms job alone.
func TestAReaderRefusesARootItCannotRead(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	root := foundRoot(t)

	if err := privtest.WithRestore(t, func() error {
		privtest.SetSecurity(t, root, "O:BGD:P(D;;RC;;;WD)(A;OICI;FA;;;WD)")

		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := EphemeralDirs(root).Check(); !errors.Is(err, windows.ERROR_ACCESS_DENIED) || !strings.Contains(err.Error(), root) {
		t.Errorf("Check(a root whose DACL denies everybody the right to read it) = %v, want %v, naming it", err,
			windows.ERROR_ACCESS_DENIED)
	}

	if err := EphemeralDirs(root).EnsureAll(); err != nil {
		t.Errorf("EnsureAll(a root whose DACL denies everybody the right to read it) = %v, want it made afresh", err)
	}

	onlyTheSystems(t, root)

	absent := filepath.Join(t.TempDir(), "absent")

	for _, dir := range []string{absent, filepath.Join(absent, "conflux")} {
		if err := EphemeralDirs(dir).Check(); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("Check(%s, which is not there) = %v, want %v", dir, err, os.ErrNotExist)
		}
	}
}

// TestCheckHoldsARootAsConfluxMakesOne: Check holds each root that is there to its owner and to whom
// its DACL grants anything, on itself or on what is made in it, as found and changing nothing: a root
// EnsureAll made passes, and one this account owns that grants Users the right to add a file to it is
// refused, naming it and Users, and left with that grant; so is one that only inherits %ProgramData%'s
// grant to Users, and one whose own DACL grants Users nothing on it and full control of what is made
// in it (inherit-only). Where no root is there Check is fs.ErrNotExist. Windows-only, so it runs in
// CI's platforms job alone.
func TestCheckHoldsARootAsConfluxMakesOne(t *testing.T) {
	t.Setenv("CONFLUX_DIR", filepath.Join(t.TempDir(), "conflux"))

	if err := Default().EnsureAll(); err != nil {
		t.Fatalf("EnsureAll: %v", err)
	}

	if err := Default().Check(); err != nil {
		t.Errorf("Check(a root EnsureAll made) = %v", err)
	}

	t.Setenv("CONFLUX_DIR", "")

	open := foundRoot(t)
	privtest.GrantUsers(t, open, windows.FILE_WRITE_DATA, windows.NO_INHERITANCE)

	parent := t.TempDir()
	privtest.ProgramDataGrant(t, parent)

	inherits := filepath.Join(parent, "conflux")
	if err := os.Mkdir(inherits, 0o700); err != nil {
		t.Fatal(err)
	}

	passes := foundRoot(t)
	privtest.SetSecurity(t, passes, "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICIIO;FA;;;BU)")

	for what, root := range map[string]string{
		"a root Users may add a file to":                          open,
		"a root inheriting %ProgramData%'s grant to Users":        inherits,
		"a root passing Users full control of what is made in it": passes,
	} {
		err := EphemeralDirs(root).Check()
		if err == nil || !strings.Contains(err.Error(), root+" is not as conflux makes") ||
			!strings.Contains(err.Error(), "Users") {
			t.Errorf("Check(%s) = %v, want a refusal naming it and Users", what, err)
		}
	}

	users := wellKnown(windows.WinBuiltinUsersSid)
	if !slices.ContainsFunc(privtest.ReadSecurity(t, open).Grantees(), users.Equals) {
		t.Errorf("Check took Users' grant from %s, which it only judges", open)
	}

	absent := filepath.Join(t.TempDir(), "absent")
	if err := (Dirs{Config: absent, State: absent, Run: filepath.Join(absent, runName)}).Check(); !errors.Is(err,
		os.ErrNotExist) {
		t.Errorf("Check(no root there) = %v, want %v", err, os.ErrNotExist)
	}
}

// TestMakeRootGoesIntoNoNameTakenMeanwhile: the way to a root in a CONFLUX_DIR is walked from the top of
// its volume, each folder judged before a name is looked up in it, and the folders missing -- made, and
// the CONFLUX_DIR in it -- are made each through a handle on the one before and held open as they are
// made, so what somebody else makes at a name meanwhile -- C:\ lets every user make a folder -- answers
// for nothing it was not judged for. Planted at the name the walk looks up, and at each it makes: a
// junction is followed and judged where the walk meets it, and refused, naming it, where it was made
// once conflux was making the name, with nothing made where it leads; a folder whose DACL lets Users
// rename what is in it is refused, naming it, with nothing made in it -- by the walk where it is looked
// up, and by makeWay where it is made; and a plain one, as a conflux making the same root at once
// makes, is gone into. Planted at the root's own name as it is looked up, a junction and a folder Users
// may rename what is in are removed as themselves, and the root made afresh. Windows-only, so it runs
// in CI's platforms job alone.
func TestMakeRootGoesIntoNoNameTakenMeanwhile(t *testing.T) {
	was := looking
	t.Cleanup(func() { looking = was })

	// fresh is a base to make made\conflux\.conflux in, with CONFLUX_DIR set to made\conflux.
	fresh := func(t *testing.T) (step, dir, root string) {
		step = filepath.Join(t.TempDir(), "made")
		dir = filepath.Join(step, "conflux")
		t.Setenv("CONFLUX_DIR", dir)

		return step, dir, Default().State
	}

	// Where looking is called on a run with nothing planted, from the walk's lookup of made on: made
	// looked up and made, conflux made, the root looked up.
	step, dir, root := fresh(t)

	var calls []string

	looking = func(p string) { calls = append(calls, p) }

	if err := Default().EnsureAll(); err != nil {
		t.Fatal(err)
	}

	first := slices.Index(calls, step)
	if first < 0 || len(calls) < first+4 || !slices.Equal(calls[first:first+4], []string{step, step, dir, root}) {
		t.Fatalf("looking was called with %q, want made looked up and made, then conflux made, then the root", calls)
	}

	phases := []string{"looked up", "made", "made, the CONFLUX_DIR", "looked up, the root"}

	for i, phase := range phases {
		for _, c := range []struct {
			name  string
			plant func(t *testing.T, at string) (elsewhere string)
			// refused is what the refusal for the plant, by its phase, holds; none where the root is made.
			refused func(step, dir, root string) [][]string
		}{
			{"a junction into a folder Users may rename what is in", func(t *testing.T, at string) string {
				open := filepath.Join(t.TempDir(), "open-to-users")
				if err := os.MkdirAll(filepath.Join(open, "real"), 0o700); err != nil {
					t.Fatal(err)
				}

				privtest.GrantUsers(t, open, fileDeleteChild, windows.NO_INHERITANCE)
				mklinkJ(t, at, filepath.Join(open, "real"))

				return filepath.Join(open, "real")
			}, func(step, dir, root string) [][]string {
				made := func(at string) []string {
					return []string{at + ", a junction or a link, was made while conflux made the way to " + root}
				}

				return [][]string{{root + " is inside ", `open-to-users, which grants `}, made(step), made(dir), nil}
			}},
			{"a folder Users may rename what is in", func(t *testing.T, at string) string {
				grantedFolder(t, at, fileDeleteChild)

				return ""
			}, func(step, dir, root string) [][]string {
				inside := func(at string) []string { return []string{root + " is inside " + at + ", which grants "} }

				return [][]string{inside(step), inside(step), inside(dir), nil}
			}},
			{"a plain folder", func(t *testing.T, at string) string {
				if err := os.Mkdir(at, 0o700); err != nil {
					t.Fatal(err)
				}

				return ""
			}, func(string, string, string) [][]string { return make([][]string, len(phases)) }},
		} {
			t.Run(c.name+", "+phase, func(t *testing.T) {
				step, dir, root := fresh(t)
				at := []string{step, step, dir, root}[i]

				var elsewhere string

				n := 0
				looking = func(p string) {
					if p == at {
						if n++; n == []int{1, 2, 1, 1}[i] {
							elsewhere = c.plant(t, p)
						}
					}
				}

				err := Default().EnsureAll()

				want := c.refused(step, dir, root)[i]
				for _, w := range want {
					if err == nil || !strings.Contains(err.Error(), w) {
						t.Errorf("EnsureAll, with %s planted at %s as it was %s, = %v, want %q", c.name, at, phase,
							err, want)

						break
					}
				}

				if len(want) == 0 {
					if err != nil {
						t.Errorf("EnsureAll, with %s planted at %s as it was %s, = %v", c.name, at, phase, err)
					} else {
						onlyTheSystems(t, root)
					}
				}

				if elsewhere != "" {
					if entries, err := os.ReadDir(elsewhere); err != nil || len(entries) != 0 {
						t.Errorf("EnsureAll made %v where the junction planted at %s leads (%v)", entries, at, err)
					}
				}

				// Refused at made, nothing is made in it.
				if at == step && len(want) != 0 && elsewhere == "" {
					if entries, err := os.ReadDir(step); err != nil || len(entries) != 0 {
						t.Errorf("EnsureAll made %v in %s, refused as it was %s (%v)", entries, step, phase, err)
					}
				}
			})
		}
	}
}
