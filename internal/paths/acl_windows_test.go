package paths

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

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

	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}

	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION,
		nil, nil, withUsers(t, sd, access), nil); err != nil {
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
		nil, nil, withUsers(t, sd, access), nil); err != nil {
		t.Fatal(err)
	}
}

// withUsers is sd's DACL with access granted to Users on the object itself.
func withUsers(t *testing.T, sd *windows.SECURITY_DESCRIPTOR, access windows.ACCESS_MASK) *windows.ACL {
	t.Helper()

	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}

	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: access,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(wellKnown(windows.WinBuiltinUsersSid)),
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
