package paths

import (
	"encoding/binary"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestEnsureAllGivesTheRootToAdministrators: the root is made SYSTEM's and
// Administrators', with a DACL %ProgramData%'s grants to Users cannot flow back into,
// and what is created beneath it afterwards inherits that.
func TestEnsureAllGivesTheRootToAdministrators(t *testing.T) {
	root := filepath.Join(t.TempDir(), "conflux")
	t.Setenv("CONFLUX_DIR", root)

	d := Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatalf("EnsureAll: %v", err)
	}

	owner, control, err := ownership(root)
	if err != nil {
		t.Fatal(err)
	}

	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Error("the root's DACL is not protected, so the parent's grants still apply")
	}

	if !Trusted(root) {
		t.Errorf("the root is owned by %s", owner)
	}

	// Idempotent: a second call finds it already done.
	if err := d.EnsureAll(); err != nil {
		t.Fatalf("EnsureAll again: %v", err)
	}

	f := filepath.Join(d.Run, "token")
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if !Trusted(f) {
		t.Error("a file created beneath the root is not trusted")
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
// is refused, naming the directory. The right to create folders there is not that: C:\
// gives it to every user, and their folder cannot take the place of one that is not theirs.
func TestEnsureAllRefusesARootAnotherAccountCanMove(t *testing.T) {
	for _, c := range []struct {
		name    string
		access  windows.ACCESS_MASK
		refused bool
	}{
		{"Users may rename what is in it", fileDeleteChild, true},
		{"Users may create folders in it", 0x4, false}, // FILE_ADD_SUBDIRECTORY
	} {
		t.Run(c.name, func(t *testing.T) {
			parent := t.TempDir()
			grant(t, parent, c.access)

			t.Setenv("CONFLUX_DIR", filepath.Join(parent, "conflux"))

			err := Default().EnsureAll()

			switch {
			case c.refused && (err == nil || !strings.Contains(err.Error(), parent)):
				t.Errorf("a root in %s was accepted, or the refusal does not name it: %v", parent, err)
			case !c.refused && err != nil:
				t.Errorf("a root in %s was refused: %v", parent, err)
			}
		})
	}
}

// grant gives Users access to dir itself, beside what its DACL grants already.
func grant(t *testing.T, dir string, access windows.ACCESS_MASK) {
	t.Helper()

	grantInherited(t, dir, access, windows.NO_INHERITANCE)
}

// grantInherited is grant, the entry passed on to what dir holds as inherit says.
func grantInherited(t *testing.T, dir string, access windows.ACCESS_MASK, inherit uint32) {
	t.Helper()

	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}

	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION,
		nil, nil, withUsers(t, sd, access, inherit), nil); err != nil {
		t.Fatal(err)
	}
}

// grantLink is grant for a link or junction: its own DACL, opened as itself, where grant's named
// calls would follow it and change the DACL of where it leads.
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

	if err := windows.SetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION,
		nil, nil, withUsers(t, sd, access, windows.NO_INHERITANCE), nil); err != nil {
		t.Fatal(err)
	}
}

// withUsers is sd's DACL with access granted to Users on the object itself, and passed on as
// inherit says.
func withUsers(t *testing.T, sd *windows.SECURITY_DESCRIPTOR, access windows.ACCESS_MASK, inherit uint32) *windows.ACL {
	t.Helper()

	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}

	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: access,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       inherit,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(sidUsers),
		},
	}}, dacl)
	if err != nil {
		t.Fatal(err)
	}

	return acl
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

	grant(t, open, fileDeleteChild)

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

// TestSecureHoldsAJunctionRoot: a root that is a junction is held to who may point it elsewhere,
// as a link is on Unix to its owner: %ProgramData% lets any user make one where conflux's root
// is not yet, leading into a directory of SYSTEM's, whose owner would answer for it. One whose
// own DACL lets Users write its attributes, enough to rewrite its target, is refused by secure
// and by Foreign, naming it; one only this account and the system may change is accepted by
// both. A root of the platform's, so no CONFLUX_DIR: no parents are read. Windows-only, so it
// runs in CI's platforms job alone.
func TestSecureHoldsAJunctionRoot(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	open := mklinkJ(t, filepath.Join(t.TempDir(), "j"), t.TempDir())
	grantLink(t, open, windows.FILE_WRITE_ATTRIBUTES)

	if err := Foreign(open); err == nil || !strings.Contains(err.Error(), open) {
		t.Errorf("Foreign(a junction Users may point elsewhere) = %v, want a refusal naming it", err)
	}

	if err := secure(open); err == nil || !strings.Contains(err.Error(), open) {
		t.Errorf("secure(a junction Users may point elsewhere) = %v, want a refusal naming it", err)
	}

	held := mklinkJ(t, filepath.Join(t.TempDir(), "j"), t.TempDir())

	if err := Foreign(held); err != nil {
		t.Errorf("Foreign(a junction only this account and the system may change) = %v", err)
	}

	if err := secure(held); err != nil {
		t.Errorf("secure(a junction only this account and the system may change) = %v", err)
	}
}

// sidUsers is BUILTIN\Users, every account on the machine.
var sidUsers = wellKnown(windows.WinBuiltinUsersSid)

// TestARootIsMadeWithItsDACL: %ProgramData% passes Users the right to create in what is made in it,
// enough to turn an empty directory into a junction, so a root is made with its own ownership and
// protected DACL set as it is created, and carries that grant not even for an instant: read as
// makeRoot leaves it, before anything else is done, and again once EnsureAll has made one. One
// already there is left as it is, for secure. Windows-only, so it runs in CI's platforms job
// alone.
func TestARootIsMadeWithItsDACL(t *testing.T) {
	parent := t.TempDir()

	// %ProgramData%'s own: Users may add a file or a folder (on a folder, writing its data or
	// appending to it), and write extended attributes and attributes, in every folder made in it.
	grantInherited(t, parent, windows.FILE_WRITE_DATA|windows.FILE_APPEND_DATA|windows.FILE_WRITE_EA|
		windows.FILE_WRITE_ATTRIBUTES, windows.SUB_CONTAINERS_ONLY_INHERIT)

	made := filepath.Join(parent, "made")
	if err := makeRoot(made); err != nil {
		t.Fatalf("makeRoot: %v", err)
	}

	onlyTheSystems(t, made)

	if err := makeRoot(made); err != nil {
		t.Errorf("makeRoot of a root already there: %v", err)
	}

	root := filepath.Join(parent, "conflux")
	t.Setenv("CONFLUX_DIR", root)

	if err := Default().EnsureAll(); err != nil {
		t.Fatalf("EnsureAll: %v", err)
	}

	onlyTheSystems(t, root)
}

// onlyTheSystems fails t unless dir belongs to SYSTEM, the Administrators or this account, under a
// protected DACL whose every entry is SYSTEM's or the Administrators'.
func onlyTheSystems(t *testing.T, dir string) {
	t.Helper()

	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}

	if owner, _, err := sd.Owner(); err != nil || !trusted(owner) {
		t.Errorf("%s belongs to %v (%v)", dir, owner, err)
	}

	if control, _, err := sd.Control(); err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("the DACL of %s is not protected (%v), so %s's grants flow into it", dir, err, filepath.Dir(dir))
	}

	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("the DACL of %s: %v, %v", dir, dacl, err)
	}

	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}

		if sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)); !sid.Equals(sidSystem) && !sid.Equals(sidAdmins) {
			t.Errorf("the DACL of %s grants %s", dir, sid)
		}
	}
}

// TestSecureRefusesARootThatBecomesAJunction: a root found unrestricted is one Users may have been
// let write, enough to turn it into a junction while it is empty, and to keep a handle that does
// so once its DACL is replaced. So the root is read again, through the handle it was judged and
// restricted through, and refused where it became one meanwhile -- here as soon as secure has
// restricted it. Windows-only, so it runs in CI's platforms job alone.
func TestSecureRefusesARootThatBecomesAJunction(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	root := filepath.Join(t.TempDir(), "conflux")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}

	elsewhere := t.TempDir()

	was := restricted
	t.Cleanup(func() { restricted = was })

	restricted = func(dir string) { mountPoint(t, dir, elsewhere) }

	if err := secure(root); err == nil || !strings.Contains(err.Error(), root+" became a junction") {
		t.Errorf("secure(a root that became a junction once restricted) = %v, want a refusal naming it", err)
	}
}

// mountPoint turns the empty directory dir into a junction leading to target, in place, as an
// account that may write its data or its attributes can.
func mountPoint(t *testing.T, dir, target string) {
	t.Helper()

	h := openToWrite(t, dir)
	defer windows.CloseHandle(h)

	if err := setMountPoint(h, target); err != nil {
		t.Fatalf("make %s a junction: %v", dir, err)
	}
}

// openToWrite opens dir as itself, to write its data and attributes.
func openToWrite(t *testing.T, dir string) windows.Handle {
	t.Helper()

	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		t.Fatal(err)
	}

	h, err := windows.CreateFile(name, windows.GENERIC_WRITE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}

	return h
}

// setMountPoint sets a mount point leading to target on the directory h holds:
// FSCTL_SET_REPARSE_POINT with REPARSE_DATA_BUFFER's MountPointReparseBuffer -- the substitute
// name, as NT looks it up, and the name to print, each counted in bytes without its NUL, in one
// buffer after the lengths.
func setMountPoint(h windows.Handle, target string) error {
	sub, print := utf16.Encode([]rune(`\??\`+target)), utf16.Encode([]rune(target))

	b := binary.LittleEndian.AppendUint32(nil, windows.IO_REPARSE_TAG_MOUNT_POINT)
	b = binary.LittleEndian.AppendUint16(b, uint16(8+2*(len(sub)+1)+2*(len(print)+1)))
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint16(b, uint16(2*len(sub)))
	b = binary.LittleEndian.AppendUint16(b, uint16(2*(len(sub)+1)))
	b = binary.LittleEndian.AppendUint16(b, uint16(2*len(print)))

	for _, c := range append(append(sub, 0), append(print, 0)...) {
		b = binary.LittleEndian.AppendUint16(b, c)
	}

	var n uint32

	return windows.DeviceIoControl(h, windows.FSCTL_SET_REPARSE_POINT, &b[0], uint32(len(b)), nil, 0, &n, nil)
}

// TestSecureFillsAFoundRoot: a handle opened on a root found unrestricted, by an account its old
// DACL let write its attributes, keeps that right once the DACL is replaced. So secure makes the
// root hold its run directory, SYSTEM's and the Administrators' as it is made, before it reads the
// root again, and the handle opened beforehand can no longer make a junction of it: a reparse
// point cannot be set on a directory that is not empty. Windows-only, so it runs in CI's platforms
// job alone.
func TestSecureFillsAFoundRoot(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	root := filepath.Join(t.TempDir(), "conflux")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}

	early := openToWrite(t, root)
	defer windows.CloseHandle(early)

	if err := secure(root); err != nil {
		t.Fatalf("secure(a root found empty) = %v", err)
	}

	onlyTheSystems(t, filepath.Join(root, runName))

	if err := setMountPoint(early, t.TempDir()); !errors.Is(err, windows.ERROR_DIR_NOT_EMPTY) {
		t.Errorf("a handle opened on the root before secure made it a junction afterwards: %v, want %v",
			err, windows.ERROR_DIR_NOT_EMPTY)
	}
}

// TestSecureHoldsWhatTheRootHolds: what a root found unrestricted holds is judged, by secure before
// it restricts the root and by Foreign, by its own owner and DACL, read without following it, and
// held to who may write it, move it or point it elsewhere: a junction Users may point elsewhere,
// though where it leads is nobody else's; a folder Users may delete, or write the attributes of,
// enough to make a junction of it while it is empty; a folder named anchor that another account
// owns, though it grants anchord what conflux grants it; and one granting anchord that also lets
// Users add to it. conflux's own layout is let through: a junction only this account and the system
// may change, and anchor\ and run\anchord\ granting anchord's service SID what makeAnchorDir
// grants it, run\anchord\sock owned by that SID, which the walk does not go into. Windows-only,
// so it runs in CI's platforms job alone.
func TestSecureHoldsWhatTheRootHolds(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	for _, c := range []struct {
		name string
		make func(t *testing.T, root string) string
	}{
		{"a junction Users may point elsewhere", func(t *testing.T, root string) string {
			j := mklinkJ(t, filepath.Join(root, "run"), t.TempDir())
			grantLink(t, j, windows.FILE_WRITE_ATTRIBUTES)

			return j
		}},
		{"a folder Users may delete", func(t *testing.T, root string) string {
			return grantedFolder(t, filepath.Join(root, "logs"), windows.DELETE)
		}},
		{"a folder Users may make a junction of", func(t *testing.T, root string) string {
			return grantedFolder(t, filepath.Join(root, "logs"), windows.FILE_WRITE_ATTRIBUTES)
		}},
		{"a folder named anchor that another account owns", func(t *testing.T, root string) string {
			dir := anchordFolder(t, filepath.Join(root, "anchor"), "")
			ownBy(t, dir, sidUsers)

			return dir
		}},
		{"a folder granting anchord that lets Users add to it", func(t *testing.T, root string) string {
			return anchordFolder(t, filepath.Join(root, "anchor"), "(A;;0x2;;;BU)")
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "conflux")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}

			held := c.make(t, root)

			if err := Foreign(root); err == nil || !strings.Contains(err.Error(), held) {
				t.Errorf("Foreign(a root holding %s) = %v, want a refusal naming it", c.name, err)
			}

			if err := secure(root); err == nil || !strings.Contains(err.Error(), held) {
				t.Errorf("secure(a root holding %s) = %v, want a refusal naming it", c.name, err)
			}
		})
	}

	for _, c := range []struct {
		name string
		make func(t *testing.T, root string)
	}{
		{"a junction only this account and the system may change", func(t *testing.T, root string) {
			mklinkJ(t, filepath.Join(root, "run"), t.TempDir())
		}},
		{"anchord's directories, and what anchord made in them", func(t *testing.T, root string) {
			sid, err := ServiceSID()
			if err != nil {
				t.Fatal(err)
			}

			anchordFolder(t, filepath.Join(root, "anchor"), "")

			if err := os.Mkdir(filepath.Join(root, runName), 0o700); err != nil {
				t.Fatal(err)
			}

			sock := filepath.Join(anchordFolder(t, filepath.Join(root, runName, "anchord"), ""), "sock")
			if err := os.WriteFile(sock, nil, 0o600); err != nil {
				t.Fatal(err)
			}

			ownBy(t, sock, sid)
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "conflux")
			if err := os.Mkdir(root, 0o700); err != nil {
				t.Fatal(err)
			}

			c.make(t, root)

			if err := Foreign(root); err != nil {
				t.Errorf("Foreign(a root holding %s) = %v", c.name, err)
			}

			if err := secure(root); err != nil {
				t.Errorf("secure(a root holding %s) = %v", c.name, err)
			}
		})
	}
}

// grantedFolder is the folder dir, made and granted access for Users.
func grantedFolder(t *testing.T, dir string, access windows.ACCESS_MASK) string {
	t.Helper()

	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	grant(t, dir, access)

	return dir
}

// anchordFolder is the folder dir, made as makeAnchorDir makes one for anchord's account --
// SYSTEM's and the Administrators', anchord's service SID let list, add, delete what is in it
// and write its attributes, and full control of what it holds, an OWNER RIGHTS entry granting
// owners nothing -- with more ACEs after, and owned by the Administrators, which this process
// may name, rather than SYSTEM.
func anchordFolder(t *testing.T, dir, more string) string {
	t.Helper()

	sid, err := ServiceSID()
	if err != nil {
		t.Fatal(err)
	}

	sd, err := windows.SecurityDescriptorFromString("O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1201ff;;;" +
		sid.String() + ")(A;OICIIO;FA;;;" + sid.String() + ")(A;OICI;RC;;;OW)" + more)
	if err != nil {
		t.Fatal(err)
	}

	if err := MakeDir(dir, sd); err != nil {
		t.Fatal(err)
	}

	return dir
}

// ownBy makes sid the owner of path, as only a process with SeRestorePrivilege enabled may name
// an owner it does not carry: this one, an Administrator's, for the moment it takes.
func ownBy(t *testing.T, path string, sid *windows.SID) {
	t.Helper()

	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY,
		&tok); err != nil {
		t.Fatal(err)
	}
	defer tok.Close()

	name, err := windows.UTF16PtrFromString("SeRestorePrivilege")
	if err != nil {
		t.Fatal(err)
	}

	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, name, &luid); err != nil {
		t.Fatal(err)
	}

	set := func(attributes uint32) {
		tp := windows.Tokenprivileges{PrivilegeCount: 1}
		tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: attributes}

		if err := windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil); err != nil {
			t.Fatal(err)
		}
	}

	set(windows.SE_PRIVILEGE_ENABLED)
	defer set(0)

	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION,
		sid, nil, nil, nil); err != nil {
		t.Fatalf("give %s to %s: %v", path, sid, err)
	}
}

// TestSecureRefusesARootWhoseDACLLetsAnotherMoveWhatIsInIt: fill keeps a handle opened under a
// found root's old DACL from making a junction of it only while nobody else may take out what fill
// puts there, so a root whose DACL lets Users delete what is in it is refused, naming the grant,
// and left as it was; one that only inherits %ProgramData%'s grant to Users, to add to a folder and
// write its attributes, passes. Windows-only, so it runs in CI's platforms job alone.
func TestSecureRefusesARootWhoseDACLLetsAnotherMoveWhatIsInIt(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "")

	root := filepath.Join(t.TempDir(), "conflux")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}

	grant(t, root, fileDeleteChild)

	if err := secure(root); err == nil || !strings.Contains(err.Error(), root) || !strings.Contains(err.Error(), sidUsers.String()) {
		t.Errorf("secure(a root whose DACL lets Users delete what is in it) = %v, want a refusal naming it and Users", err)
	}

	if _, control, err := ownership(root); err != nil || control&windows.SE_DACL_PROTECTED != 0 {
		t.Errorf("the refused root was restricted (%v); a refusal must change nothing", err)
	}

	parent := t.TempDir()
	grantInherited(t, parent, windows.FILE_WRITE_DATA|windows.FILE_APPEND_DATA|windows.FILE_WRITE_EA|
		windows.FILE_WRITE_ATTRIBUTES, windows.SUB_CONTAINERS_ONLY_INHERIT)

	inherits := filepath.Join(parent, "conflux")
	if err := os.Mkdir(inherits, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := secure(inherits); err != nil {
		t.Errorf("secure(a root inheriting %%ProgramData%%'s grant to Users) = %v", err)
	}
}
