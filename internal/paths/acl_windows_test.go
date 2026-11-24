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

	widen(t, d.Root)

	if adminsAlone(d.Root) {
		t.Fatal("a DACL granting Users reads as SYSTEM's and the Administrators' alone")
	}

	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	if !adminsAlone(d.Root) {
		t.Error("EnsureAll left the root granting Users")
	}
}

// TestAWidenedDACLIsTakenBackBesideAnchordsFiles: what anchord's own account wrote in the two
// directories it writes, anchor\ and run\anchord\, is that account's, and is no reason to
// refuse a root whose DACL somebody widened: the root is restricted again, rather than refused
// at every start for ever. anchor.root\ is SYSTEM's, so a file another account owns there is
// refused as anywhere else, and each of the three directories is still held to the rule itself.
func TestAWidenedDACLIsTakenBackBesideAnchordsFiles(t *testing.T) {
	d := Dirs{Root: filepath.Join(t.TempDir(), ".conflux")}
	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	for _, dir := range []string{d.AnchorDir(), d.RootAnchorDir(), d.DaemonRun()} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	// lsFile is a file in dir that LOCAL SERVICE owns, as anchord running as that account leaves.
	lsFile := func(dir, name string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}

		giveTo(t, path, windows.WinLocalServiceSid)

		if Trusted(path) {
			t.Fatal("a file LOCAL SERVICE owns reads as trusted")
		}

		return path
	}

	lsFile(d.AnchorDir(), "bootstrap.json")
	lsFile(d.DaemonRun(), "sock.lock")

	widen(t, d.Root)

	if err := d.EnsureAll(); err != nil {
		t.Fatalf("EnsureAll beside anchord's own files: %v", err)
	}

	if !adminsAlone(d.Root) {
		t.Error("EnsureAll left the root granting Users")
	}

	// In anchor.root, which LOCAL SERVICE writes nothing in, its file is another account's.
	foreign := lsFile(d.RootAnchorDir(), "bootstrap.json")
	widen(t, d.Root)

	if err := d.EnsureAll(); err == nil {
		t.Error("EnsureAll took a root whose anchor.root holds a file another account owns")
	}

	if err := os.Remove(foreign); err != nil {
		t.Fatal(err)
	}

	// One of those directories made by another account is refused, as anything else is.
	giveTo(t, d.RootAnchorDir(), windows.WinLocalServiceSid)
	widen(t, d.Root)

	if err := d.EnsureAll(); err == nil {
		t.Error("EnsureAll took a root whose anchor.root another account owns")
	}
}

// widen gives path a protected DACL granting Users full control, as somebody with the right
// to change it might.
func widen(t *testing.T, path string) {
	t.Helper()

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

	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		t.Fatal(err)
	}
}

// adminsAlone reports whether path's DACL grants SYSTEM and the Administrators alone.
func adminsAlone(path string) bool {
	sd, _, err := ownership(path)

	return err == nil && grantsAdminsAlone(sd)
}

// giveTo makes the well-known account sid the owner of path: naming an owner other than
// oneself takes SeRestorePrivilege, which an Administrator holds and enables here for the
// one call.
func giveTo(t *testing.T, path string, sid windows.WELL_KNOWN_SID_TYPE) {
	t.Helper()

	var tok windows.Token
	if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
		t.Fatal(err)
	}
	defer tok.Close()

	var luid windows.LUID

	name, _ := windows.UTF16PtrFromString("SeRestorePrivilege")
	if err := windows.LookupPrivilegeValue(nil, name, &luid); err != nil {
		t.Fatal(err)
	}

	set := func(attrs uint32) {
		tp := windows.Tokenprivileges{PrivilegeCount: 1}
		tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: attrs}

		if err := windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil); err != nil {
			t.Fatal(err)
		}
	}

	set(windows.SE_PRIVILEGE_ENABLED)
	defer set(0)

	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION,
		wellKnown(sid), nil, nil, nil); err != nil {
		t.Fatalf("give %s to another account: %v", path, err)
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
