package paths

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// childSystemData, set, makes TestSystemDataIsTheSystems's child print systemData and exit.
const childSystemData = "CONFLUX_TEST_PROGRAMDATA"

// systemDataAtInit is SystemData as this package's initialisation left it, before pathstest's, in a test
// that links it, keeps it in the temporary directory: what conflux itself reads %ProgramData% through.
var systemDataAtInit = SystemData

// TestSystemDataIsTheSystems: %ProgramData%, where the installation's root and an elevated reader's
// temporary anchorctl are kept, is the system's (systemData), never the environment's, which an elevated
// process takes from the user's registry, and that user's processes that are not elevated may write:
// ProgramData, ALLUSERSPROFILE, SystemDrive, SystemRoot and windir naming another volume change neither it
// nor Default, in this process, nor in a child started with that environment. Asked of SystemData as
// conflux's initialisation leaves it (systemDataAtInit), not as this binary's tests keep it, in their
// temporary directory (pathstest, which client_windows_test links), and SystemData put back to it for
// Default. Windows-only, so it runs in CI's platforms job alone.
func TestSystemDataIsTheSystems(t *testing.T) {
	if os.Getenv(childSystemData) == "1" {
		fmt.Print(systemData())
		os.Exit(0)
	}

	want := systemData()
	if filepath.VolumeName(want) == "" || !strings.EqualFold(want[len(filepath.VolumeName(want)):], `\ProgramData`) {
		t.Fatalf("systemData = %s, want \\ProgramData on a volume", want)
	}

	const elsewhere = `Q:\elsewhere`

	t.Setenv("SystemDrive", filepath.VolumeName(elsewhere))

	for _, name := range []string{"ProgramData", "ALLUSERSPROFILE", "SystemRoot", "windir"} {
		t.Setenv(name, elsewhere)
	}

	if got := systemDataAtInit(); got != want {
		t.Errorf("SystemData, with the environment naming %s, = %s, want %s", elsewhere, got, want)
	}

	inData(t, systemDataAtInit())

	if got := Default().State; got != filepath.Join(want, DirName) {
		t.Errorf("Default().State, with the environment naming %s, = %s, want it in %s", elsewhere, got, want)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestSystemDataIsTheSystems$") //nolint:gosec // this test binary
	cmd.Env = append(os.Environ(), childSystemData+"=1")

	if out, err := cmd.Output(); err != nil || string(out) != want {
		t.Errorf("systemData, in a child started with the environment naming %s, = %q (%v), want %s", elsewhere,
			out, err, want)
	}
}
