package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// pointSudoLink is serveRelease's on Windows, where an update makes no link for sudo: nothing.
func pointSudoLink(*testing.T) {}

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

// TestUninstallTakesThePathEntry: the machine's PATH loses the directory install.ps1 added,
// however it is spelled, and nothing else.
func TestUninstallTakesThePathEntry(t *testing.T) {
	for _, c := range []struct{ path, want string }{
		{`%SystemRoot%\system32;C:\Program Files\conflux;C:\tools`, `%SystemRoot%\system32;C:\tools`},
		{`C:\tools;C:\Program Files\conflux\`, `C:\tools`},
		{`C:\tools;c:\program files\CONFLUX`, `C:\tools`},
		{`C:\tools`, `C:\tools`},
	} {
		if got := withoutDir(c.path, `C:\Program Files\conflux`); got != c.want {
			t.Errorf("withoutDir(%q) = %q, want %q", c.path, got, c.want)
		}
	}
}

// TestUpdatePutsThePathEntry: an update that installs conflux where there was none puts its
// directory on the machine's PATH, as install.ps1 does: at the end, where no entry names it
// already, however spelled; and uninstall takes it out again.
func TestUpdatePutsThePathEntry(t *testing.T) {
	const dir = `C:\Program Files\conflux`

	for _, c := range []struct{ path, want string }{
		{`%SystemRoot%\system32;C:\tools`, `%SystemRoot%\system32;C:\tools;` + dir},
		{`C:\tools;`, `C:\tools;` + dir},
		{``, dir},
		{`C:\tools;c:\program files\CONFLUX\`, `C:\tools;c:\program files\CONFLUX\`},
		{dir + `;C:\tools`, dir + `;C:\tools`},
	} {
		got := withDir(c.path, dir)
		if got != c.want {
			t.Errorf("withDir(%q) = %q, want %q", c.path, got, c.want)
		}

		if back := withoutDir(got, dir); back != withoutDir(c.path, dir) {
			t.Errorf("withoutDir(withDir(%q)) = %q, which is not the PATH without it", c.path, back)
		}
	}
}
