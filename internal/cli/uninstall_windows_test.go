package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/privcheck"
	"github.com/veil-net/conflux/internal/privtest"
)

// plantLink makes link a junction to the folder target.
func plantLink(t *testing.T, link, target string) {
	t.Helper()

	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v\n%s", err, out)
	}
}

// plantForeign makes path a file another account owns: LOCAL SERVICE's.
func plantForeign(t *testing.T, path string) {
	t.Helper()

	if err := os.WriteFile(path, []byte("planted"), 0o600); err != nil {
		t.Fatal(err)
	}

	sid, err := windows.CreateWellKnownSid(windows.WinLocalServiceSid)
	if err != nil {
		t.Fatal(err)
	}

	privtest.SetOwner(t, path, sid)
}

// TestUninstallRemovesAJunctionAtAnEphemeralRootsName: an ephemeral run's root outside the
// installation's is conflux's by its name, so a junction there -- here to a folder of SYSTEM's and the
// Administrators' holding an identity, as an installation's root does -- is no root of conflux's, and
// uninstall removes it as itself, listed, exit 0: nothing where it leads read, made, stopped or
// removed, no lock taken there. Windows-only, so it runs in CI's platforms job alone.
func TestUninstallRemovesAJunctionAtAnEphemeralRootsName(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	d := configured(t)

	theirs := t.TempDir()
	if err := os.WriteFile(filepath.Join(theirs, "manifest.b64"), []byte("identity"), 0o600); err != nil {
		t.Fatal(err)
	}

	privtest.SetSecurity(t, theirs, "O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")

	junction := filepath.Join(t.TempDir(), "conflux-ephemeral")
	plantLink(t, junction, theirs)

	defer func(was func() []string) { ephemeralCandidates = was }(ephemeralCandidates)
	ephemeralCandidates = func() []string { return []string{junction} }

	var reaped []string

	was := removeEphemeral
	defer func() { removeEphemeral = was }()

	removeEphemeral = func(e paths.Dirs, unlock func(), r daemon.Reporter) error {
		reaped = append(reaped, e.State)

		return was(e, unlock, r)
	}

	standInService(t, &removing{fakeManager: fakeManager{d: d}})
	recordAccounts(t)

	out, errOut, code := capture(t, "uninstall", "--yes")
	if code != ExitOK || !strings.Contains(out, "  "+junction+"\n") {
		t.Errorf("uninstall beside a junction at an ephemeral root's name exited %d, want %d listing %s:\n%s%s",
			code, ExitOK, junction, out, errOut)
	}

	if len(reaped) > 0 {
		t.Errorf("uninstall took the lock of %q, and stopped what was left there", reaped)
	}

	if held := names(t, theirs); !slices.Equal(held, []string{"manifest.b64"}) {
		t.Errorf("uninstall left %s, where the junction led, holding %q, want what it held alone", theirs, held)
	}

	if _, err := os.Lstat(junction); !os.IsNotExist(err) {
		t.Errorf("uninstall left the junction %s (Lstat: %v)", junction, err)
	}
}
