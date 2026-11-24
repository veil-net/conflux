package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/windows/svc"

	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/paths"
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
// stopped cleanly before the exit code that said otherwise arrived.
func TestTheServiceReportsStoppedOnce(t *testing.T) {
	t.Cleanup(paths.UseRoot(t.TempDir()))

	h := &handler{sup: &daemon.Supervisor{Dirs: paths.Default(), Ready: make(chan struct{})}}
	statuses := make(chan svc.Status, 8)

	specific, exitCode := h.Execute(nil, make(chan svc.ChangeRequest), statuses)
	close(statuses)

	var states []svc.State
	for st := range statuses {
		states = append(states, st.State)
	}

	if len(states) != 1 || states[0] != svc.StartPending {
		t.Errorf("Execute reported %v, want only StartPending", states)
	}

	if specific || exitCode != 0 || h.code != ExitNoConfig {
		t.Errorf("a service with nothing to start returned %v, %d (code %d); want a clean stop, 78 in the log", specific, exitCode, h.code)
	}

	// What stops it is said where the service's output goes, which serveAsService makes the
	// event log: the SCM's record of the exit says only that it failed.
	var errw bytes.Buffer

	was := ui.Errw
	ui.Errw = &errw

	t.Cleanup(func() { ui.Errw = was })

	failed := &handler{sup: h.sup, setup: errors.New("no disk")}

	if specific, exitCode := failed.Execute(nil, make(chan svc.ChangeRequest), make(chan svc.Status, 8)); !specific || exitCode != ExitError {
		t.Errorf("a service that could not make its directories returned %v, %d; want a failure the SCM restarts", specific, exitCode)
	}

	if !strings.Contains(errw.String(), "no disk") {
		t.Errorf("a service that could not make its directories wrote %q, which does not say why", errw.String())
	}
}
