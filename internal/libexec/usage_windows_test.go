package libexec

import (
	"path/filepath"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/paths"
)

// TestTheUsageCopyIsTheCallersOwn: the temporary anchorctl help runs where nothing is extracted
// is the account's that asked, as well as SYSTEM's and the Administrators': held to those two
// alone, as the extracted pair is, it would not run for a user who is not elevated.
func TestTheUsageCopyIsTheCallersOwn(t *testing.T) {
	anchortest.Require(t)

	bin, done, err := ForUsage(paths.Dirs{Root: filepath.Join(t.TempDir(), "nothing-extracted")})
	if err != nil {
		t.Fatalf("ForUsage: %v", err)
	}
	defer done()

	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}

	sd, err := windows.GetNamedSecurityInfo(bin, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}

	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		t.Fatalf("%s has no DACL: %v", bin, err)
	}

	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, i, &ace) != nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}

		if (*windows.SID)(unsafe.Pointer(&ace.SidStart)).Equals(user.User.Sid) {
			return
		}
	}

	t.Errorf("%s grants %s nothing: %s", bin, user.User.Sid, sd)
}
