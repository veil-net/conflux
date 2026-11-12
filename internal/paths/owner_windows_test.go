package paths

import (
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestRestrictToOwnerKeepsTheOwnersAccess: a file restricted to its owner is still the
// owner's to read and write, and its DACL is protected and grants the account, SYSTEM and
// Administrators alone -- not Users, which the temporary directory's inherited ACEs would.
func TestRestrictToOwnerKeepsTheOwnersAccess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "k.pem")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := RestrictToOwner(path, false); err != nil {
		t.Fatal(err)
	}

	if b, err := os.ReadFile(path); err != nil || string(b) != "secret" {
		t.Fatalf("the owner cannot read the file back: %v", err)
	}

	if err := os.WriteFile(path, []byte("again"), 0o600); err != nil {
		t.Fatalf("the owner cannot write the file: %v", err)
	}

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}

	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		t.Errorf("the DACL is not protected: %v", err)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}

	allowed := map[string]bool{currentUser().String(): true, sidSystem.String(): true, sidAdmins.String(): true}

	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}

		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !allowed[sid.String()] {
			t.Errorf("the DACL grants %s", sid)
		}
	}

	if dacl.AceCount != 3 {
		t.Errorf("the DACL has %d entries, want 3", dacl.AceCount)
	}
}
