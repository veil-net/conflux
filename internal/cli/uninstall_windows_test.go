package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// TestUninstallLeavesTheSystemsCmd: the cmd.exe uninstall leaves behind to remove the
// installation's directory is the system's, wherever %SystemRoot% points.
func TestUninstallLeavesTheSystemsCmd(t *testing.T) {
	t.Setenv("SystemRoot", t.TempDir())

	sys, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}

	if got, err := cmdExe(); err != nil || !strings.EqualFold(got, filepath.Join(sys, "cmd.exe")) {
		t.Errorf("cmdExe() = %q, %v; want the system directory's, %s", got, err, filepath.Join(sys, "cmd.exe"))
	}
}
