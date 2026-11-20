package paths

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/veil-net/conflux/internal/privtest"
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

	s := privtest.ReadSecurity(t, path)
	if !s.Protected {
		t.Error("the DACL is not protected")
	}

	allowed := map[string]bool{currentUser().String(): true, sidSystem.String(): true, sidAdmins.String(): true}

	for _, e := range s.Entries {
		if !allowed[e.SID.String()] {
			t.Errorf("the DACL grants %s", e.SID)
		}
	}

	if len(s.Entries) != 3 {
		t.Errorf("the DACL has %d entries, want 3", len(s.Entries))
	}
}
