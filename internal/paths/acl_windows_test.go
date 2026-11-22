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
// (ElevatedDefaultOwner), and root it in a folder only SYSTEM and the Administrators may change
// (privtest.ServiceTemp), rather than in the profile of the administrator running them, where %TEMP%
// is.
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
	inData(t, t.TempDir())

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

// fileDeleteChild is FILE_DELETE_CHILD: on a directory, the right to delete or rename what is in it.
const fileDeleteChild = 0x40

// TestEnsureAllJudgesNoFolderAboveARoot: the folder the root is in, and every folder above it, is the
// system's, never judged: one whose DACL lets Users rename what is in it, one inside such a folder, one
// reached through a junction into such a folder, and one through a junction Users may point elsewhere --
// a junction followed, never taken for a file -- each has its root made where it leads, the
// Administrators' under SYSTEM's and their DACL alone, and passes the readers' check. Windows-only, so it
// runs in CI's platforms job alone.
func TestEnsureAllJudgesNoFolderAboveARoot(t *testing.T) {
	made := func(t *testing.T, dir string) {
		t.Helper()

		inData(t, dir)

		d := Default()
		if err := d.EnsureAll(); err != nil {
			t.Fatalf("EnsureAll(a root at %s) = %v", dir, err)
		}

		onlyTheSystems(t, d.State)

		if err := d.Check(); err != nil {
			t.Errorf("Check(a root at %s) = %v", dir, err)
		}
	}

	for _, under := range []string{"", "data"} {
		t.Run("Users may rename what is in a folder above, "+under, func(t *testing.T) {
			parent := t.TempDir()
			privtest.GrantUsers(t, parent, fileDeleteChild, windows.NO_INHERITANCE)

			dir := filepath.Join(parent, under)
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}

			made(t, dir)
		})
	}

	t.Run("a junction into a folder Users may rename what is in", func(t *testing.T) {
		open := filepath.Join(t.TempDir(), "open-to-users")
		if err := os.MkdirAll(filepath.Join(open, "real", "data"), 0o700); err != nil {
			t.Fatal(err)
		}

		privtest.GrantUsers(t, open, fileDeleteChild, windows.NO_INHERITANCE)

		junction := mklinkJ(t, filepath.Join(t.TempDir(), "j"), filepath.Join(open, "real"))

		made(t, filepath.Join(junction, "data"))

		if _, err := os.Lstat(filepath.Join(open, "real", "data", DirName)); err != nil {
			t.Errorf("the root was not made where the junction leads: %v", err)
		}
	})

	t.Run("a junction Users may point elsewhere", func(t *testing.T) {
		retargeted := mklinkJ(t, filepath.Join(t.TempDir(), "j"), t.TempDir())
		grantLink(t, retargeted, windows.FILE_WRITE_ATTRIBUTES)

		made(t, retargeted)
	})
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
			inData(t, t.TempDir())

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

	inData(t, t.TempDir())

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

// TestEnsureAllRemovesAFileNotAsConfluxMakesIt: each file conflux keeps in a root is judged as a folder of
// conflux's is (ours), for SYSTEM in an installation's: one this administrator owns -- as an earlier
// conflux left the service's copy and the lock files on a Windows client, writing them in an
// administrator's process, where that administrator's unelevated processes could change them for SYSTEM
// to read or run -- one Users may read, or a junction, is removed as itself, where the junction leads
// untouched, and nothing made in its place. One as conflux makes it is kept. Ours refuses each, saying who
// could do what, and holds one conflux made. Windows-only, so it runs in CI's platforms job alone.
func TestEnsureAllRemovesAFileNotAsConfluxMakesIt(t *testing.T) {
	elsewhere := t.TempDir()

	kept := filepath.Join(elsewhere, "kept")
	if err := os.WriteFile(kept, []byte("not conflux's"), 0o600); err != nil {
		t.Fatal(err)
	}

	write := func(t *testing.T, p string) {
		if err := os.WriteFile(p, []byte("planted"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	plants := map[string]func(t *testing.T, p string){
		"a junction": func(t *testing.T, p string) { mklinkJ(t, p, elsewhere) },
		"a file Users may read": func(t *testing.T, p string) {
			write(t, p)
			privtest.GrantUsers(t, p, windows.FILE_READ_DATA, windows.NO_INHERITANCE)
		},
		"a file this administrator owns": func(t *testing.T, p string) {
			write(t, p)
			privtest.SetOwner(t, p, currentUser())
		},
	}

	inData(t, t.TempDir())

	d := Default()

	for _, p := range []string{d.ConfigFile(), d.StateFile(), d.ManifestFile(), d.PrivilegeFile(), d.LockFile(),
		d.ServeLockFile(), d.ServiceExecutable()} {
		for name, plant := range plants {
			t.Run(filepath.Base(p)+"/"+name, func(t *testing.T) {
				if err := d.EnsureAll(); err != nil {
					t.Fatal(err)
				}

				if err := os.RemoveAll(p); err != nil {
					t.Fatal(err)
				}

				plant(t, p)

				switch err := d.Ours(p); {
				case err == nil:
					t.Errorf("Ours(%s at %s) = nil, want a refusal", name, p)
				case name != "a junction" && !strings.Contains(err.Error(), ", who could change it or read what is in it)"):
					t.Errorf("Ours(%s at %s) = %v, want a refusal saying who could do what", name, p, err)
				}

				if err := d.EnsureAll(); err != nil {
					t.Fatalf("EnsureAll(%s at %s) = %v", name, p, err)
				}

				if _, err := os.Lstat(p); !errors.Is(err, os.ErrNotExist) {
					t.Errorf("EnsureAll left %s at %s (Lstat: %v)", name, p, err)
				}

				if b, err := os.ReadFile(kept); err != nil || string(b) != "not conflux's" {
					t.Errorf("where a junction at %s led lost what is in it: %q, %v", p, b, err)
				}
			})
		}
	}

	write(t, d.ServiceExecutable())

	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	if err := d.Ours(d.ServiceExecutable()); err != nil {
		t.Errorf("Ours(a copy as conflux makes it) = %v", err)
	}
}

// TestARootOnANetworkVolumeIsRefused: who owns what a network volume holds, and whom its DACLs
// grant, are the accounts of the machine serving it, which this one cannot judge, so a root on
// one is refused by EnsureAll and by the readers' check alike, naming the network volume, as the
// device the top of its volume is open on says and not as it is spelled: reached by its UNC path, or
// through a drive mapped to the share. Nothing is made there. A link to that drive at the root's name
// is no root of conflux's: the readers' check refuses it, and EnsureAll removes it as itself, and
// makes the root here, nothing made on the share. A data folder on the share is refused the same, and a
// link naming the share itself, on the way to the data folder, is refused as a link before anything
// follows it (and further in TestALinkLeadingOffThisMachineOrNowhereIsRefused). The share is a folder of
// this machine's, reached through its own server. Windows-only, so it runs in CI's platforms job alone,
// and skipped where the machine will not share a folder.
func TestARootOnANetworkVolumeIsRefused(t *testing.T) {
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

	for _, data := range []string{unc, filepath.Join(drive, "conflux")} {
		inData(t, data)

		if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), data) ||
			!strings.Contains(err.Error(), " is on a network volume") {
			t.Errorf("EnsureAll(a data folder of %s) = %v, want a refusal naming it and the network volume", data, err)
		}
	}

	// A link naming the share itself, on the way to the data folder, is refused as a link before
	// anything is looked up through it (walk), and not as the network volume it leads to.
	toShare := dirSymlink(t, filepath.Join(t.TempDir(), "share"), share)
	data := filepath.Join(toShare, "conflux")
	inData(t, data)

	if err := Default().EnsureAll(); err == nil ||
		!strings.Contains(err.Error(), "resolve "+data+": "+toShare+" is a link conflux cannot follow") ||
		!strings.Contains(err.Error(), "another machine") {
		t.Errorf("EnsureAll(a data folder of %s) = %v, want a refusal naming the link %s and another machine", data,
			err, toShare)
	}

	if _, err := os.Lstat(filepath.Join(dir, "conflux", DirName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("EnsureAll made a root in a data folder on a network volume it refused (%v)", err)
	}
}

// TestALinkLeadingOffThisMachineOrNowhereIsRefused: a link on the way to the data folder that names a
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
		inData(t, dir)

		root := Default().State

		if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), refusal(dir)) ||
			!strings.Contains(err.Error(), "may be on another machine") {
			t.Errorf("EnsureAll(a data folder of %s) = %v, want %q, saying it may be on another machine", dir, err,
				refusal(dir))
		}

		if err := Default().Check(); err == nil || !strings.Contains(err.Error(), refusal(filepath.Dir(root))) ||
			!strings.Contains(err.Error(), "may be on another machine") {
			t.Errorf("Check(%s), data folder %s, = %v, want %q, saying it may be on another machine", root, dir,
				err, refusal(filepath.Dir(root)))
		}
	}

	for _, dir := range []string{dangling, filepath.Join(dangling, "conflux")} {
		inData(t, dir)

		if err := Default().EnsureAll(); err == nil || !strings.Contains(err.Error(), dangling+" is a link conflux cannot follow") {
			t.Errorf("EnsureAll(a data folder of %s) = %v, want a refusal naming the link to nothing", dir, err)
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
	if err := rootAt(made).makeRoot(made); err != nil {
		t.Fatalf("makeRoot: %v", err)
	}

	onlyTheSystems(t, made)

	if err := rootAt(made).makeRoot(made); err != nil {
		t.Errorf("makeRoot of a root already there: %v", err)
	}

	inData(t, parent)

	if err := Default().EnsureAll(); err != nil {
		t.Fatalf("EnsureAll: %v", err)
	}

	onlyTheSystems(t, Default().State)
}

// TestAnInstallationInAProfileIsMade: the boot service runs as SYSTEM, which trusts no other account
// with its root, but the folder the root is in is not judged: a data folder granting this account full
// control, passed on to what is made in it, as the profile of the administrator running conflux does, has
// its root made, SYSTEM's and the Administrators' alone, which passes the readers' check. Windows-only,
// so it runs in CI's platforms job alone.
func TestAnInstallationInAProfileIsMade(t *testing.T) {
	profile := filepath.Join(t.TempDir(), "profile")
	if err := os.Mkdir(profile, 0o700); err != nil {
		t.Fatal(err)
	}

	privtest.Grant(t, profile, currentUser(), fileAllAccess, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)

	inData(t, profile)

	if err := Default().EnsureAll(); err != nil {
		t.Fatalf("EnsureAll(an installation inside a folder granting this account full control) = %v", err)
	}

	onlyTheSystems(t, Default().State)

	if err := Default().Check(); err != nil {
		t.Errorf("Check(an installation inside a folder granting this account full control) = %v", err)
	}
}

// onlyTheSystems fails t unless dir belongs to the Administrators, as everything conflux makes does,
// under a protected DACL whose every entry is SYSTEM's or the Administrators'.
func onlyTheSystems(t *testing.T, dir string) {
	t.Helper()

	s := privtest.ReadSecurity(t, dir)

	if !s.Owner.Equals(sidAdmins) {
		t.Errorf("%s belongs to %v, want the Administrators", dir, s.Owner)
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

// TestAReaderRefusesARootItCannotRead: %ProgramData% lets any account make .conflux where conflux has
// not made it yet, and give it a DACL denying everybody the right to read it, so only a root
// that is not there, or under a directory that is not, is taken by the readers' check for none,
// fs.ErrNotExist, unread: one this account may not open is refused, naming it and the denial, rather
// than taken for a run's or for none; and EnsureAll, which may remove it whatever its DACL says, makes
// the root afresh. Owned by the Guests, a group this process's token does not hold: an owner is let
// read a DACL whatever the DACL says, and an Administrator's token holds Users. Windows-only, so it
// runs in CI's platforms job alone.
func TestAReaderRefusesARootItCannotRead(t *testing.T) {
	root := foundRoot(t)

	if err := privtest.WithRestore(t, func() error {
		privtest.SetSecurity(t, root, "O:BGD:P(D;;RC;;;WD)(A;OICI;FA;;;WD)")

		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := rootAt(root).Check(); !errors.Is(err, windows.ERROR_ACCESS_DENIED) || !strings.Contains(err.Error(), root) {
		t.Errorf("Check(a root whose DACL denies everybody the right to read it) = %v, want %v, naming it", err,
			windows.ERROR_ACCESS_DENIED)
	}

	if err := rootAt(root).EnsureAll(); err != nil {
		t.Errorf("EnsureAll(a root whose DACL denies everybody the right to read it) = %v, want it made afresh", err)
	}

	onlyTheSystems(t, root)

	absent := filepath.Join(t.TempDir(), "absent")

	for _, dir := range []string{absent, filepath.Join(absent, "conflux")} {
		if err := rootAt(dir).Check(); !errors.Is(err, os.ErrNotExist) {
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
	inData(t, t.TempDir())

	if err := Default().EnsureAll(); err != nil {
		t.Fatalf("EnsureAll: %v", err)
	}

	if err := Default().Check(); err != nil {
		t.Errorf("Check(a root EnsureAll made) = %v", err)
	}

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
		err := rootAt(root).Check()
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

// TestMakeRootGoesIntoNoNameTakenMeanwhile: the root is looked up in the folder it is in, held, and
// nowhere else, and made there through a handle on that folder, so what somebody else makes at its name
// as conflux looks it up -- %ProgramData% lets every user make a folder -- is never followed: a junction
// into a folder Users may rename what is in, and a folder Users may rename what is in, are removed as
// themselves and the root made afresh, SYSTEM's and the Administrators' alone, with nothing made where
// the junction leads; a plain folder, as a conflux making the same root at once makes, is taken as the
// root. Windows-only, so it runs in CI's platforms job alone.
func TestMakeRootGoesIntoNoNameTakenMeanwhile(t *testing.T) {
	was := looking
	t.Cleanup(func() { looking = was })

	for name, plant := range map[string]func(t *testing.T, at string) (elsewhere string){
		"a junction into a folder Users may rename what is in": func(t *testing.T, at string) string {
			open := filepath.Join(t.TempDir(), "open-to-users")
			if err := os.MkdirAll(filepath.Join(open, "real"), 0o700); err != nil {
				t.Fatal(err)
			}

			privtest.GrantUsers(t, open, fileDeleteChild, windows.NO_INHERITANCE)
			mklinkJ(t, at, filepath.Join(open, "real"))

			return filepath.Join(open, "real")
		},
		"a folder Users may rename what is in": func(t *testing.T, at string) string {
			grantedFolder(t, at, fileDeleteChild)

			return ""
		},
		"a plain folder": func(t *testing.T, at string) string {
			if err := os.Mkdir(at, 0o700); err != nil {
				t.Fatal(err)
			}

			return ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			inData(t, t.TempDir())

			root := Default().State

			var elsewhere string

			n := 0
			looking = func(p string) {
				if p == root {
					if n++; n == 1 {
						elsewhere = plant(t, p)
					}
				}
			}

			if err := Default().EnsureAll(); err != nil {
				t.Fatalf("EnsureAll, with %s planted at the root's name as it was looked up, = %v", name, err)
			}

			if n == 0 {
				t.Fatalf("the root's name %s was never looked up", root)
			}

			onlyTheSystems(t, root)

			if elsewhere != "" {
				if entries, err := os.ReadDir(elsewhere); err != nil || len(entries) != 0 {
					t.Errorf("EnsureAll made %v where the junction planted at the root's name leads (%v)", entries, err)
				}
			}
		})
	}
}

// rootAt is the Dirs of a root at root, the configuration and the state in it and the run directory
// inside it: for a test that judges or makes a root there.
func rootAt(root string) Dirs {
	return Dirs{Config: root, State: root, Run: filepath.Join(root, runName)}
}
