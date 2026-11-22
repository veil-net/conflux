package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/pathstest"
	"github.com/veil-net/conflux/internal/privtest"
)

// TestStatusRefusesAJunctionRootToAUsersFolder: status holds the root, .conflux in the system's data
// folder, to paths' check before it reads anything in it by name: a root in a data folder reached through
// a junction to a folder Users may add files and folders to, which passes their grant on to it -- one
// they could have put a configuration in -- is refused, naming the root and Users, and the configuration
// there is not read. Windows-only, so it runs in CI's platforms job alone.
func TestStatusRefusesAJunctionRootToAUsersFolder(t *testing.T) {
	folder := t.TempDir()
	privtest.ProgramDataGrant(t, folder)

	planted := filepath.Join(folder, paths.DirName)
	if err := os.Mkdir(planted, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := config.Save(paths.Dirs{Root: planted}, &config.Config{Mode: config.ModeProxy,
		Taints: []string{"planted"}}); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(t.TempDir(), "conflux")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", dir, folder).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v\n%s", err, out)
	}

	root := pathstest.RootedIn(t, dir).Root

	out, errOut, code := capture(t, "status")
	if code != ExitError || !strings.Contains(errOut, root+" is not as conflux makes") ||
		!strings.Contains(errOut, "Users") {
		t.Errorf("status of a root through a junction to a folder Users may write exited %d, want %d refusing %s "+
			"and naming Users:\n%s", code, ExitError, root, errOut)
	}

	if strings.Contains(out, "planted") {
		t.Errorf("status read the configuration in a root it refuses:\n%s", out)
	}
}
