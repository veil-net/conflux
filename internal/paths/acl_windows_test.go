package paths

import (
	"os"
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
	users := wellKnown(windows.WinBuiltinUsersSid)

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

			sd, err := windows.GetNamedSecurityInfo(parent, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
			if err != nil {
				t.Fatal(err)
			}

			dacl, _, err := sd.DACL()
			if err != nil {
				t.Fatal(err)
			}

			acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
				AccessPermissions: c.access,
				AccessMode:        windows.GRANT_ACCESS,
				Inheritance:       windows.NO_INHERITANCE,
				Trustee: windows.TRUSTEE{
					TrusteeForm:  windows.TRUSTEE_IS_SID,
					TrusteeType:  windows.TRUSTEE_IS_GROUP,
					TrusteeValue: windows.TrusteeValueFromSID(users),
				},
			}}, dacl)
			if err != nil {
				t.Fatal(err)
			}

			if err := windows.SetNamedSecurityInfo(parent, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION,
				nil, nil, acl, nil); err != nil {
				t.Fatal(err)
			}

			t.Setenv("CONFLUX_DIR", filepath.Join(parent, "conflux"))

			err = Default().EnsureAll()

			switch {
			case c.refused && (err == nil || !strings.Contains(err.Error(), parent)):
				t.Errorf("a root in %s was accepted, or the refusal does not name it: %v", parent, err)
			case !c.refused && err != nil:
				t.Errorf("a root in %s was refused: %v", parent, err)
			}
		})
	}
}
