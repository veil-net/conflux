package libexec

import (
	"path/filepath"
	"slices"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/paths"
)

// TestAUsageCopyIsItsRunners: the anchorctl help runs from a temporary directory is granted to
// the account running it, which need not be an administrator, and a set's binaries to SYSTEM
// and the Administrators alone: a copy restricted as a set is could not be executed by such an
// account. CI runs elevated, where a set's DACL would let the runner in all the same, so it is
// the grants themselves that are checked, on the copy ForUsage made and the set Ensure made;
// and the copy's DACL is checked to be its own, protected, since the one %TEMP% passes on
// grants the runner already.
func TestAUsageCopyIsItsRunners(t *testing.T) {
	anchortest.Require(t)

	t.Setenv("CONFLUX_DIR", filepath.Join(t.TempDir(), "conflux"))

	tmp := t.TempDir()
	t.Setenv("TMP", tmp)
	t.Setenv("TEMP", tmp)

	tu, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}

	user := tu.User.Sid
	d := paths.Default()

	bin, done, err := ForUsage(d)
	if err != nil {
		t.Fatalf("ForUsage: %v", err)
	}

	defer done()

	sids, protected := allowed(t, bin)
	if !slices.ContainsFunc(sids, user.Equals) {
		t.Errorf("the temporary anchorctl %s grants nothing to %s, the account that ran it: one that is not an "+
			"administrator could not execute it", bin, user)
	}

	if !protected {
		t.Errorf("the temporary anchorctl %s keeps the DACL its directory passed on, not one of its own", bin)
	}

	tools, err := Ensure(d)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	admins, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)

	sids, _ = allowed(t, tools.Anchorctl)
	for _, sid := range sids {
		if !sid.Equals(system) && !sid.Equals(admins) {
			t.Errorf("the set's anchorctl %s grants %s, beside SYSTEM and the Administrators", tools.Anchorctl, sid)
		}
	}
}

// allowed is whom path's DACL allows anything, and whether the DACL is protected: its own,
// with nothing from its directory merged in.
func allowed(t *testing.T, path string) (sids []*windows.SID, protected bool) {
	t.Helper()

	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}

	control, _, err := sd.Control()
	if err != nil {
		t.Fatal(err)
	}

	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}

	for i := range uint32(dacl.AceCount) {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			t.Fatal(err)
		}

		if ace.Header.AceType == windows.ACCESS_ALLOWED_ACE_TYPE {
			sids = append(sids, (*windows.SID)(unsafe.Pointer(&ace.SidStart)))
		}
	}

	return sids, control&windows.SE_DACL_PROTECTED != 0
}
