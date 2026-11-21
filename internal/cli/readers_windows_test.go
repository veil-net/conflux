package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/privtest"
	"golang.org/x/sys/windows"
)

// notAsConfluxMakesIt makes the file p this administrator's, as an earlier conflux left the service's copy
// on a Windows client: not as conflux makes a file of its own, which the Administrators own.
func notAsConfluxMakesIt(t *testing.T, p string) {
	t.Helper()

	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		t.Fatal(err)
	}

	privtest.SetOwner(t, p, user.User.Sid)
}

// TestStatusRefusesAJunctionRootToAUsersFolder: %ProgramData% lets any account make a junction
// where conflux's root is not yet, and a CONFLUX_DIR can be one, so status holds the root, .conflux
// inside it, to paths' check before it reads anything in it by name: a root reached through a junction
// to a folder Users may add files and folders to, which passes their grant on to it -- one they could
// have put a configuration in -- is refused, naming the root and Users, and the configuration there is
// not read. Windows-only, so it runs in CI's platforms job alone.
func TestStatusRefusesAJunctionRootToAUsersFolder(t *testing.T) {
	folder := t.TempDir()
	privtest.ProgramDataGrant(t, folder)

	planted := filepath.Join(folder, paths.DirName)
	if err := os.Mkdir(planted, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := config.Save(paths.Dirs{Config: planted, State: planted}, &config.Config{Mode: config.ModeProxy,
		Taints: []string{"planted"}}); err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(t.TempDir(), "conflux")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", dir, folder).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v\n%s", err, out)
	}

	t.Setenv("CONFLUX_DIR", dir)

	root := paths.Default().State

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
