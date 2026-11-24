package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// TestUninstallLeavesTheSystemsCmd: the cmd.exe uninstall leaves behind to remove the
// installation's directory is the system's, wherever %SystemRoot% points, and so is the ping it
// waits with: named by its full path, and started in the system directory, so that neither a
// ping.exe nor a ping.bat where uninstall was typed runs in its place, as Administrator.
func TestUninstallLeavesTheSystemsCmd(t *testing.T) {
	t.Setenv("SystemRoot", t.TempDir())

	sys, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}

	dir := filepath.Join(t.TempDir(), "conflux")

	cmd, err := removalCommand(dir)
	if err != nil {
		t.Fatal(err)
	}

	if !strings.EqualFold(cmd.Path, filepath.Join(sys, "cmd.exe")) {
		t.Errorf("the removal runs %s, not the system directory's cmd.exe, %s", cmd.Path, filepath.Join(sys, "cmd.exe"))
	}

	if !strings.EqualFold(cmd.Dir, sys) {
		t.Errorf("the removal starts in %q, not the system directory, %s", cmd.Dir, sys)
	}

	line := cmd.SysProcAttr.CmdLine
	if ping := `"` + filepath.Join(sys, "PING.EXE") + `"`; !strings.Contains(line, ping) {
		t.Errorf("the removal does not wait with %s, by its full path, quoted: %s", ping, line)
	}

	if !strings.Contains(line, `rmdir /s /q "`+dir+`"`) {
		t.Errorf("the removal does not remove %s: %s", dir, line)
	}
}
