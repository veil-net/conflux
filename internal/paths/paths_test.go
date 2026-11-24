package paths

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestTheRootIsTheMachinesDotConflux: everything conflux keeps is in one directory, .conflux,
// at an absolute path in the platform's place for a service's data, and every file and
// directory the supervisor or a command writes is inside it.
func TestTheRootIsTheMachinesDotConflux(t *testing.T) {
	r := platformRoot()

	if !filepath.IsAbs(r) || filepath.Base(r) != ".conflux" {
		t.Fatalf("platformRoot() = %q, want an absolute path to a directory named .conflux", r)
	}

	d := Dirs{Root: r}

	for _, p := range []string{
		d.ConfigFile(), d.StateFile(), d.ManifestFile(), d.DaemonConfigFile(), d.AnchorDir(), d.RootAnchorDir(),
		d.ServiceExecutable(), d.Libexec(), d.RunDir(), d.DaemonRun(), d.Socket(), d.TokenFile(), d.PrivilegeFile(),
		d.LockFile(), d.ServeLockFile(), d.DaemonPIDFile(), d.ReadyFile(),
	} {
		if rel, err := filepath.Rel(r, p); err != nil || rel == "." || strings.HasPrefix(rel, "..") {
			t.Errorf("%s is not inside %s", p, r)
		}
	}

	if l := d.LogFile(); l != "" && filepath.Dir(l) != r {
		t.Errorf("the log file %s is not in %s", l, r)
	}
}

// TestUseRootMovesDefaultAndPutsItBack: the one way a test roots conflux elsewhere, an
// ephemeral run beside it rather than in the system's run directory.
func TestUseRootMovesDefaultAndPutsItBack(t *testing.T) {
	dir := t.TempDir()

	restore := UseRoot(dir)
	if got := Default().Root; got != dir {
		t.Errorf("Default().Root = %q under UseRoot, want %q", got, dir)
	}

	if got := EphemeralCandidates(); len(got) != 1 || got[0] != dir+"-ephemeral" {
		t.Errorf("EphemeralCandidates() = %v under UseRoot, want only %s", got, dir+"-ephemeral")
	}

	restore()

	if got := Default().Root; got != platformRoot() {
		t.Errorf("Default().Root = %q after restore, want the platform's %q", got, platformRoot())
	}
}
