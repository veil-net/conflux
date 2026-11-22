package service

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows/svc"
)

// TestAStoppingServiceRuns: a service the SCM says is starting, running or stopping has its process
// still there, and runs; one stopped does not. tidy asks Running before it stops the service for an
// update, and a service stopping that it took for one not running would leave its supervisor holding
// the serve lock, and be called one run by hand.
func TestAStoppingServiceRuns(t *testing.T) {
	for state, want := range map[svc.State]bool{
		svc.Stopped:      false,
		svc.StartPending: true,
		svc.Running:      true,
		svc.StopPending:  true,
	} {
		if got := runs(state); got != want {
			t.Errorf("runs(%d) = %v, want %v", state, got, want)
		}
	}
}

// TestAPercentIsNeverRegistered: the SCM expands every %NAME% in a service's command line at each start,
// so an executable or an argument holding a % -- a CONFLUX_DIR such as C:\%OS% -- would have SYSTEM run
// another file than the one conflux placed: Install refuses either, before it asks the SCM anything.
// Under a CONFLUX_DIR of the test's own, so that an Install that went ahead would register a service of
// that scope's name, removed again. Windows-only, so it runs in CI's platforms job alone.
func TestAPercentIsNeverRegistered(t *testing.T) {
	root := filepath.Join(t.TempDir(), "conflux")
	t.Setenv("CONFLUX_DIR", root)

	for _, line := range [][]string{
		{`C:\%OS%\.conflux\conflux.exe`, "serve", "--dir", root},
		{filepath.Join(root, ".conflux", "conflux.exe"), "serve", "--dir", `C:\%OS%`},
	} {
		err := scm{}.Install(line[0], line[1:]...)
		if err == nil {
			t.Cleanup(func() { _ = scm{}.Remove() })
		}

		if err == nil || !strings.Contains(err.Error(), "%") || !strings.Contains(err.Error(), "CONFLUX_DIR") {
			t.Errorf("Install(%q) = %v, want it refused, naming the %% and a CONFLUX_DIR without one", line, err)
		}
	}
}
