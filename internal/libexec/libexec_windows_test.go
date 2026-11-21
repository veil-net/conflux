package libexec

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/pathstest"
	"github.com/veil-net/conflux/internal/privtest"
)

// TestAUsageCopyIsGuardedForWhoRunsIt: the anchorctl a reader runs from a temporary directory is guarded
// for the account running it. Elevated, as CI runs, it is in a folder of its own in %ProgramData%, never
// the account's own %TEMP%, and the folder and the copy are SYSTEM's and the Administrators' alone, under
// a protected DACL granting the account nothing by its own SID, whose processes that are not elevated
// could otherwise change it between its write and its run; done removes both. Not elevated, the copy is
// granted to the account, which need not be an administrator, under a DACL of its own, since the one
// %TEMP% passes on grants the runner already. A set's binaries are SYSTEM's and the Administrators'
// alone, read from the DACL its extraction wrote.
func TestAUsageCopyIsGuardedForWhoRunsIt(t *testing.T) {
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
	if err != nil || done == nil {
		t.Fatalf("ForUsage = %s, %v, want a temporary copy to remove", bin, err)
	}

	dir := filepath.Dir(bin)

	if windows.GetCurrentProcessToken().IsElevated() {
		if filepath.Dir(dir) != paths.ProgramData() {
			t.Errorf("an elevated reader's temporary anchorctl is %s, want it in a folder of its own in %s", bin,
				paths.ProgramData())
		}

		for _, p := range []string{dir, bin} {
			s := privtest.ReadSecurity(t, p)
			if !s.Protected {
				t.Errorf("%s keeps the DACL its folder passed on, not one of its own", p)
			}

			for _, sid := range s.Grantees() {
				if !sid.Equals(privtest.System) && !sid.Equals(privtest.Admins) {
					t.Errorf("%s, an elevated reader's, grants %s, beside SYSTEM and the Administrators", p, sid)
				}
			}
		}
	} else {
		copied := privtest.ReadSecurity(t, bin)
		if !slices.ContainsFunc(copied.Grantees(), user.Equals) {
			t.Errorf("the temporary anchorctl %s grants nothing to %s, the account that ran it: one that is not an "+
				"administrator could not execute it", bin, user)
		}

		if !copied.Protected {
			t.Errorf("the temporary anchorctl %s keeps the DACL its directory passed on, not one of its own", bin)
		}
	}

	done()

	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Errorf("done left the temporary anchorctl's folder %s (Lstat: %v)", dir, err)
	}

	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	tools, err := Extract(d)
	if err != nil {
		t.Fatalf("Extract: %v", err)
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

	d := pathstest.DirsIn(t, filepath.Join(t.TempDir(), "conflux"))

	if err := os.MkdirAll(d.Libexec(), 0o700); err != nil {
		t.Fatal(err)
	}

	privtest.DenyOwnersTheirDACL(t, d.Libexec())

	if _, err := Ensure(d); err != nil {
		t.Fatalf("Ensure in a directory that refuses what is made in it a DACL given afterwards: %v", err)
	}
}
