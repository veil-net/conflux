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
