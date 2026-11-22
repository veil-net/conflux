package paths

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// childProgramData, set, makes TestProgramDataIsTheSystems's child print systemProgramData and exit.
const childProgramData = "CONFLUX_TEST_PROGRAMDATA"

// programDataAtInit is ProgramData as this package's initialisation left it, before pathstest's, in a test
// that links it, keeps it in the temporary directory: what conflux itself reads %ProgramData% through.
var programDataAtInit = ProgramData

// TestProgramDataIsTheSystems: %ProgramData%, where the platform's roots, an ephemeral run's and an
// elevated reader's temporary anchorctl are kept, is the system's (systemProgramData), never the
// environment's, which an elevated process takes from the user's registry, and that user's processes that
// are not elevated may write: ProgramData, ALLUSERSPROFILE, SystemDrive, SystemRoot and windir naming
// another volume change neither it nor Default, in this process, nor in a child started with that
// environment. Asked of ProgramData as conflux's initialisation leaves it (programDataAtInit), not as this
// binary's tests keep it, in their temporary directory (pathstest, which client_windows_test links), and
// ProgramData put back to it for Default. Windows-only, so it runs in CI's platforms job alone.
func TestProgramDataIsTheSystems(t *testing.T) {
	if os.Getenv(childProgramData) == "1" {
		fmt.Print(systemProgramData())
		os.Exit(0)
	}

	want := systemProgramData()
	if filepath.VolumeName(want) == "" || !strings.EqualFold(want[len(filepath.VolumeName(want)):], `\ProgramData`) {
		t.Fatalf("systemProgramData = %s, want \\ProgramData on a volume", want)
	}

	const elsewhere = `Q:\elsewhere`

	t.Setenv("CONFLUX_DIR", "")
	t.Setenv("SystemDrive", filepath.VolumeName(elsewhere))

	for _, name := range []string{"ProgramData", "ALLUSERSPROFILE", "SystemRoot", "windir"} {
		t.Setenv(name, elsewhere)
	}

	if got := programDataAtInit(); got != want {
		t.Errorf("ProgramData, with the environment naming %s, = %s, want %s", elsewhere, got, want)
	}

	defer func(was func() string) { ProgramData = was }(ProgramData)
	ProgramData = programDataAtInit

	if got := Default().State; got != filepath.Join(want, "conflux") {
		t.Errorf("Default().State, with the environment naming %s, = %s, want it in %s", elsewhere, got, want)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestProgramDataIsTheSystems$") //nolint:gosec // this test binary
	cmd.Env = append(os.Environ(), childProgramData+"=1")

	if out, err := cmd.Output(); err != nil || string(out) != want {
		t.Errorf("systemProgramData, in a child started with the environment naming %s, = %q (%v), want %s", elsewhere,
			out, err, want)
	}
}
