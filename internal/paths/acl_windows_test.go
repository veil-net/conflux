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

// fileDeleteChild is FILE_DELETE_CHILD: on a directory, the right to delete or rename what is in it.
const fileDeleteChild = 0x40

// TestEnsureAllJudgesNoFolderAboveARoot: a CONFLUX_DIR, and every folder above its root, is the user's
// choice, never judged: one inside a folder whose DACL lets Users rename what is in it, directly or with a
// folder made on the way, one reached through a junction into such a folder, and one through a junction
// Users may point elsewhere -- a junction followed, never taken for a file -- each has its root made where
// it leads, the Administrators' under SYSTEM's and their DACL alone, and passes the readers' check and
// uninstall's walk. Windows-only, so it runs in CI's platforms job alone.
func TestEnsureAllJudgesNoFolderAboveARoot(t *testing.T) {
	made := func(t *testing.T, dir string) {
		t.Helper()

		t.Setenv("CONFLUX_DIR", dir)

		d := Default()
		if err := d.EnsureAll(); err != nil {
			t.Fatalf("EnsureAll(a root at %s) = %v", dir, err)
		}

		onlyTheSystems(t, d.State)

		if err := d.Check(); err != nil {
			t.Errorf("Check(a root at %s) = %v", dir, err)
		}

		if err := d.WalkWays(); err != nil {
			t.Errorf("WalkWays(a root at %s) = %v", dir, err)
		}
	}

	for _, under := range []string{"conflux", filepath.Join("made", "conflux")} {
		t.Run("Users may rename what is in a folder above, "+under, func(t *testing.T) {
			parent := t.TempDir()
			privtest.GrantUsers(t, parent, fileDeleteChild, windows.NO_INHERITANCE)

			made(t, filepath.Join(parent, under))
		})
	}

	t.Run("a junction into a folder Users may rename what is in", func(t *testing.T) {
		open := filepath.Join(t.TempDir(), "open-to-users")
		if err := os.MkdirAll(filepath.Join(open, "real"), 0o700); err != nil {
			t.Fatal(err)
		}

		privtest.GrantUsers(t, open, fileDeleteChild, windows.NO_INHERITANCE)

		junction := mklinkJ(t, filepath.Join(t.TempDir(), "j"), filepath.Join(open, "real"))

		made(t, filepath.Join(junction, "conflux"))

		if _, err := os.Lstat(filepath.Join(open, "real", "conflux", DirName)); err != nil {
			t.Errorf("the root was not made where the junction leads: %v", err)
		}
	})

	t.Run("a junction Users may point elsewhere", func(t *testing.T) {
		retargeted := mklinkJ(t, filepath.Join(t.TempDir(), "j"), t.TempDir())
		grantLink(t, retargeted, windows.FILE_WRITE_ATTRIBUTES)

		made(t, filepath.Join(retargeted, "conflux"))
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

	t.Setenv("CONFLUX_DIR", t.TempDir())

	d := Default()

	for _, p := range []string{d.ConfigFile(), d.StateFile(), d.ManifestFile(), d.PrivilegeFile(), d.WayFile(),
		d.LockFile(), d.ServeLockFile(), d.ServiceExecutable()} {
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
// not trust. So x, y and the CONFLUX_DIR, made for <temp>\x\y\conflux, are SYSTEM's and the
// Administrators' alone, and y, taken as a root itself, passes the readers' check. Windows-only, so it
// runs in CI's platforms job alone.
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
}

// TestAnInstallationInAProfileIsMade: the boot service runs as SYSTEM, which trusts no other account
// with its root, but the way to the root is the user's choice and not judged: a CONFLUX_DIR inside a
// folder granting this account full control, as the profile of the administrator running conflux does,
// has its root made, SYSTEM's and the Administrators' alone, which passes the readers' check, and so has
// an ephemeral run's root inside that CONFLUX_DIR. Windows-only, so it runs in CI's platforms job alone.
func TestAnInstallationInAProfileIsMade(t *testing.T) {
	profile := filepath.Join(t.TempDir(), "profile")
	if err := os.Mkdir(profile, 0o700); err != nil {
		t.Fatal(err)
	}

	privtest.Grant(t, profile, currentUser(), fileAllAccess, windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)

	root := filepath.Join(profile, "conflux")
	t.Setenv("CONFLUX_DIR", root)

	if err := Default().EnsureAll(); err != nil {
		t.Fatalf("EnsureAll(an installation inside a folder granting this account full control) = %v", err)
	}

	onlyTheSystems(t, Default().State)

	if err := Default().Check(); err != nil {
		t.Errorf("Check(an installation inside a folder granting this account full control) = %v", err)
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

// TestAnEphemeralRootIsJudgedForTheAdministrators: %ProgramData% lets any account make
// conflux-ephemeral first, and the administrator's own processes that are not elevated could make one and
// fill it with a held lock, a readiness marker and an anchorctl of their own, for an elevated reader to
// take for a run and run. So an ephemeral run's root is judged for the Administrators, never the account
// conflux runs as by its own SID: one that account owns, or one granting it anything, is refused, naming
// it, and EnsureAll makes it afresh, the Administrators', which then passes. Windows-only, so it runs in
// CI's platforms job alone, which runs elevated.
func TestAnEphemeralRootIsJudgedForTheAdministrators(t *testing.T) {
	user := currentUser().String()

	for what, sddl := range map[string]string{
		"owned by the administrator's own account": "O:" + user + "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)",
		"granting the administrator's own account": "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FA;;;" + user + ")",
	} {
		t.Run(what, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), ephemeralName)
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}

			privtest.SetSecurity(t, root, sddl)

			if err := EphemeralDirs(root).Check(); err == nil || !strings.Contains(err.Error(), root+" is not as conflux makes") {
				t.Errorf("Check(an ephemeral root %s) = %v, want a refusal naming it", what, err)
			}

			if err := EphemeralDirs(root).EnsureAll(); err != nil {
				t.Fatalf("EnsureAll(an ephemeral root %s) = %v", what, err)
			}

			if err := EphemeralDirs(root).Check(); err != nil {
				t.Errorf("Check(the ephemeral root EnsureAll made afresh) = %v", err)
			}
		})
	}
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
// its volume, and the folders missing -- made, and the CONFLUX_DIR in it -- are made each through a
// handle on the one before and held open as they are made, so what somebody else makes at a name
// meanwhile -- C:\ lets every user make a folder -- is never followed where conflux made the name.
// Planted at the name the walk looks up, and at each it makes: a junction is followed where the walk
// meets it, as any on the way is, and refused, naming it, where it was made once conflux was making the
// name, with nothing made where it leads; a folder, whether its DACL lets Users rename what is in it or
// it is a plain one, as a conflux making the same root at once makes, is gone into, unjudged, as every
// folder above a root is. Planted at the root's own name as it is looked up, a junction and a folder
// Users may rename what is in are removed as themselves, and the root made afresh. Windows-only, so it
// runs in CI's platforms job alone.
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

				return [][]string{nil, made(step), made(dir), nil}
			}},
			{"a folder Users may rename what is in", func(t *testing.T, at string) string {
				grantedFolder(t, at, fileDeleteChild)

				return ""
			}, func(string, string, string) [][]string { return make([][]string, len(phases)) }},
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

				if elsewhere != "" && len(want) != 0 {
					if entries, err := os.ReadDir(elsewhere); err != nil || len(entries) != 0 {
						t.Errorf("EnsureAll made %v where the junction planted at %s leads (%v)", entries, at, err)
					}
				}
			})
		}
	}
}
