package libexec

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/privtest"
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

	copied := privtest.ReadSecurity(t, bin)
	if !slices.ContainsFunc(copied.Grantees(), user.Equals) {
		t.Errorf("the temporary anchorctl %s grants nothing to %s, the account that ran it: one that is not an "+
			"administrator could not execute it", bin, user)
	}

	if !copied.Protected {
		t.Errorf("the temporary anchorctl %s keeps the DACL its directory passed on, not one of its own", bin)
	}

	tools, err := Ensure(d)
	if err != nil {
		t.Fatalf("Ensure: %v", err)
	}

	for _, sid := range privtest.ReadSecurity(t, tools.Anchorctl).Grantees() {
		if !sid.Equals(privtest.System) && !sid.Equals(privtest.Admins) {
			t.Errorf("the set's anchorctl %s grants %s, beside SYSTEM and the Administrators", tools.Anchorctl, sid)
		}
	}
}

// TestAStagingDirectoryIsMadeWithItsDACL: a set is written in a staging directory made with its
// ownership and DACL set as it is created, never carrying what the directory it is made in passes
// on: here a denial of WRITE_DAC to whoever owns what is made there, which a staging directory made
// and then restricted would be refused its DACL by, so Ensure would fail. Windows-only, so it runs
// in CI's platforms job alone.
func TestAStagingDirectoryIsMadeWithItsDACL(t *testing.T) {
	anchortest.Require(t)

	t.Setenv("CONFLUX_DIR", filepath.Join(t.TempDir(), "conflux"))

	d := paths.Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	if err := os.MkdirAll(d.Libexec(), 0o700); err != nil {
		t.Fatal(err)
	}

	privtest.DenyOwnersTheirDACL(t, d.Libexec())

	if _, err := Ensure(d); err != nil {
		t.Fatalf("Ensure in a directory that refuses what is made in it a DACL given afterwards: %v", err)
	}
}
