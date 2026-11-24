package paths

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// TestEnsureAllGivesTheRootToAdministrators: the root is made SYSTEM's and
// Administrators', with a DACL %ProgramData%'s grants to Users cannot flow back into,
// and what is created beneath it afterwards inherits that.
func TestEnsureAllGivesTheRootToAdministrators(t *testing.T) {
	root := filepath.Join(t.TempDir(), ".conflux")

	d := Dirs{Root: root}
	if err := d.EnsureAll(); err != nil {
		t.Fatalf("EnsureAll: %v", err)
	}

	sd, owner, err := ownership(root)
	if err != nil {
		t.Fatal(err)
	}

	if control, _, err := sd.Control(); err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Error("the root's DACL is not protected, so the parent's grants still apply")
	}

	if !Trusted(root) {
		t.Errorf("the root is owned by %s", owner)
	}

	// Idempotent: a second call finds it already done.
	if err := d.EnsureAll(); err != nil {
		t.Fatalf("EnsureAll again: %v", err)
	}

	f := d.TokenFile()
	if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}

	if !Trusted(f) {
		t.Error("a file created beneath the root is not trusted")
	}
}

// TestEnsureAllTakesBackAWidenedDACL: a root that is Administrators' and protected, but whose
// DACL somebody gave to another account, is restricted again rather than taken as done.
func TestEnsureAllTakesBackAWidenedDACL(t *testing.T) {
	d := Dirs{Root: filepath.Join(t.TempDir(), ".conflux")}
	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	users := wellKnown(windows.WinBuiltinUsersSid)

	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windows.GENERIC_ALL, AccessMode: windows.GRANT_ACCESS,
		Inheritance: windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT,
		Trustee: windows.TRUSTEE{TrusteeForm: windows.TRUSTEE_IS_SID, TrusteeType: windows.TRUSTEE_IS_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(users)},
	}}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if err := windows.SetNamedSecurityInfo(d.Root, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}

	adminsAlone := func() bool {
		sd, _, err := ownership(d.Root)

		return err == nil && onlyAdmins(sd)
	}

	if adminsAlone() {
		t.Fatal("a DACL granting Users reads as SYSTEM's and the Administrators' alone")
	}

	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	if !adminsAlone() {
		t.Error("EnsureAll left the root granting Users")
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
