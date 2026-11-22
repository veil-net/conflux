package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/windows/svc"

	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/pathstest"
	"github.com/veil-net/conflux/internal/privcheck"
	"github.com/veil-net/conflux/internal/ui"
)

// TestOnlyATransientExitAsksForARestart: the SCM's recovery restarts what reports a
// failure, so only the supervisor's exit 1 may; nothing to start, and a configuration no
// restart changes, stop as cleanly as a stop does.
func TestOnlyATransientExitAsksForARestart(t *testing.T) {
	for code, want := range map[int]bool{ExitOK: false, ExitNoConfig: false, ExitChildFailed: false, ExitError: true} {
		specific, exitCode := scmExit(code)

		if specific != want || (exitCode != 0) != want {
			t.Errorf("scmExit(%d) = %v, %d; want a failure the SCM restarts: %v", code, specific, exitCode, want)
		}
	}
}

// TestTheServiceReportsStoppedOnce: Execute leaves Stopped to svc.Run, which reports it
// with the exit Execute returns. Reported here as well, the SCM read the service as
// stopped cleanly before the exit code that said otherwise arrived. A service with nothing to
// start stops cleanly; one whose EnsureAll refuses its root -- its data folder beneath a file --
// ends as any failed start does, a failure the SCM restarts, saying why.
func TestTheServiceReportsStoppedOnce(t *testing.T) {
	pathstest.RootedIn(t, t.TempDir())

	h := &handler{sup: &daemon.Supervisor{Dirs: paths.Default(), Ready: make(chan struct{})}}

	states, specific, exitCode := execute(h)
	if !slices.Equal(states, []svc.State{svc.StartPending}) {
		t.Errorf("Execute reported %v, want only StartPending", states)
	}

	if specific || exitCode != 0 || h.code != ExitNoConfig {
		t.Errorf("a service with nothing to start returned %v, %d (code %d); want a clean stop, 78 in the log", specific, exitCode, h.code)
	}

	parent := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(parent, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	pathstest.RootedIn(t, filepath.Join(parent, "data"))

	var errBuf bytes.Buffer

	defer func(was io.Writer) { ui.Errw = was }(ui.Errw)
	ui.Errw = &errBuf

	refused := &handler{sup: &daemon.Supervisor{Dirs: paths.Default(), Ready: make(chan struct{})}}

	states, specific, exitCode = execute(refused)
	if !slices.Equal(states, []svc.State{svc.StartPending}) {
		t.Errorf("Execute, its root refused, reported %v, want only StartPending", states)
	}

	if !specific || exitCode != ExitError || refused.code != ExitError || !strings.Contains(errBuf.String(), parent) {
		t.Errorf("a service whose root EnsureAll refuses returned %v, %d (code %d), saying\n%s\nwant a failure the SCM "+
			"restarts, naming %s", specific, exitCode, refused.code, errBuf.String(), parent)
	}
}

// execute runs h as the SCM would, asking nothing of it, until it returns: the states it reported
// on the way, and what it returned for svc.Run to report.
func execute(h *handler) (states []svc.State, specific bool, exitCode uint32) {
	statuses := make(chan svc.Status, 8)

	specific, exitCode = h.Execute(nil, make(chan svc.ChangeRequest), statuses)
	close(statuses)

	for st := range statuses {
		states = append(states, st.State)
	}

	return states, specific, exitCode
}

// TestAPercentIsNeverRegistered: the SCM expands every %NAME% in a service's command line at each start, so
// a service executable's path holding a % would have SYSTEM run another file than the one conflux placed
// and judged. Every command that registers the service refuses it before it makes anything
// (refusePercent): those that go through handOver, and register. Each exits 1 naming the %, with nothing
// made and the service manager, the test's stand-in, asked nothing. Elevated, as CI's platforms job runs it, and as the commands are told they are here, so that
// nothing but the refusal stops them. Windows-only, so it runs in that job alone.
func TestAPercentIsNeverRegistered(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	parent := filepath.Join(t.TempDir(), "%OS%")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}

	pathstest.RootedIn(t, parent)

	manifest := filepath.Join(t.TempDir(), "manifest.b64")
	if err := os.WriteFile(manifest, []byte("e30="), 0o600); err != nil {
		t.Fatal(err)
	}

	mgr := &fakeManager{}
	standInService(t, mgr)

	for _, args := range [][]string{
		{"install"}, {"up"}, {"proxy", "8080=127.0.0.1:3000"}, {"observe"}, {"enrol", "--manifest", manifest},
		{"start"}, {"register"},
	} {
		_, errOut, code := capture(t, args...)

		if code != ExitError || !strings.Contains(errOut, "%") {
			t.Errorf("conflux %s exited %d, saying\n%s\nwant it refused, exit 1, naming the %%",
				strings.Join(args, " "), code, errOut)
		}

		if left, err := os.ReadDir(parent); err != nil || len(left) > 0 {
			t.Errorf("conflux %s made %v in %s before it refused (%v)", strings.Join(args, " "), left, parent, err)
		}
	}

	if len(mgr.installs) > 0 || mgr.restarts > 0 {
		t.Errorf("the service manager was asked to register %q and restart %d times", mgr.installs, mgr.restarts)
	}
}
