package paths

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// childProgramData, set, makes TestProgramDataIsTheSystems's child print ProgramData and exit.
const childProgramData = "CONFLUX_TEST_PROGRAMDATA"

// TestProgramDataIsTheSystems: %ProgramData%, where the platform's roots, an ephemeral run's and an
// elevated reader's temporary anchorctl are kept, is the system's, never the environment's, which an
// elevated process takes from the user's registry, and that user's processes that are not elevated may
// write: ProgramData, ALLUSERSPROFILE, SystemDrive, SystemRoot and windir naming somewhere else change
// neither ProgramData nor Default, in this process, nor in a child started with that environment.
// Windows-only, so it runs in CI's platforms job alone.
func TestProgramDataIsTheSystems(t *testing.T) {
	if os.Getenv(childProgramData) == "1" {
		fmt.Print(ProgramData())
		os.Exit(0)
	}

	want := ProgramData()
	if filepath.VolumeName(want) == "" || !strings.EqualFold(want[len(filepath.VolumeName(want)):], `\ProgramData`) {
		t.Fatalf("ProgramData = %s, want \\ProgramData on a volume", want)
	}

	elsewhere := t.TempDir()

	t.Setenv("CONFLUX_DIR", "")

	for _, name := range []string{"ProgramData", "ALLUSERSPROFILE", "SystemRoot", "windir"} {
		t.Setenv(name, elsewhere)
	}

	t.Setenv("SystemDrive", filepath.VolumeName(elsewhere))

	if got := ProgramData(); got != want {
		t.Errorf("ProgramData, with the environment naming %s, = %s, want %s", elsewhere, got, want)
	}

	if got := Default().State; got != filepath.Join(want, "conflux") {
		t.Errorf("Default().State, with the environment naming %s, = %s, want it in %s", elsewhere, got, want)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestProgramDataIsTheSystems$") //nolint:gosec // this test binary
	cmd.Env = append(os.Environ(), childProgramData+"=1")

	if out, err := cmd.Output(); err != nil || string(out) != want {
		t.Errorf("ProgramData, in a child started with the environment naming %s, = %q (%v), want %s", elsewhere, out,
			err, want)
	}
}
