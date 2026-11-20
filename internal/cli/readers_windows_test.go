package cli

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/privtest"
)

// TestStatusRefusesAJunctionRootToAUsersFolder: %ProgramData% lets any account make a junction
// where conflux's root is not yet, and a CONFLUX_DIR can be one, so status holds the root to paths'
// check before it reads anything in it by name: a junction leading to a folder Users may add files
// and folders to -- one they could have put a configuration in -- is refused, naming the root and
// Users, and the configuration there is not read. Windows-only, so it runs in CI's platforms job
// alone.
func TestStatusRefusesAJunctionRootToAUsersFolder(t *testing.T) {
	folder := t.TempDir()
	privtest.ProgramDataGrant(t, folder)

	if err := config.Save(paths.Dirs{Config: folder, State: folder}, &config.Config{Mode: config.ModeProxy,
		Taints: []string{"planted"}}); err != nil {
		t.Fatal(err)
	}

	root := filepath.Join(t.TempDir(), "conflux")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", root, folder).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v\n%s", err, out)
	}

	t.Setenv("CONFLUX_DIR", root)

	out, errOut, code := capture(t, "status")
	if code != ExitError || !strings.Contains(errOut, root) || !strings.Contains(errOut, "Users") {
		t.Errorf("status of a junction root to a folder Users may write exited %d, want %d naming it and Users:\n%s",
			code, ExitError, errOut)
	}

	if strings.Contains(out, "planted") {
		t.Errorf("status read the configuration in a root it refuses:\n%s", out)
	}
}
