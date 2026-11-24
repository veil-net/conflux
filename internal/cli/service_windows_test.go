package cli

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/windows/svc"

	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/paths"
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
	_, errw := captureUI(t)

	failed := &handler{sup: h.sup, setup: errors.New("no disk")}

	if specific, exitCode := failed.Execute(nil, make(chan svc.ChangeRequest), make(chan svc.Status, 8)); !specific || exitCode != ExitError {
		t.Errorf("a service that could not make its directories returned %v, %d; want a failure the SCM restarts", specific, exitCode)
	}

	if !strings.Contains(errw.String(), "no disk") {
		t.Errorf("a service that could not make its directories wrote %q, which does not say why", errw.String())
	}
}

// TestTheEventLogTakesALineAnEvent: what the service says reaches the event log a line an event,
// each line as anchord's are split (daemon.LineWriter, whose own test holds its line ends, a line
// in pieces and one that never ends), and an empty one written as none. Whichever goroutine speaks
// writes to it, so lines written at once each arrive whole.
func TestTheEventLogTakesALineAnEvent(t *testing.T) {
	var got []string

	w := newEventWriter(func(eid uint32, msg string) error {
		if eid != eventID {
			t.Errorf("event %d, want %d", eid, eventID)
		}

		got = append(got, msg)

		return nil
	})

	const blank = "one\n\r\n\ntwo\n"

	if n, err := w.Write([]byte(blank)); n != len(blank) || err != nil {
		t.Fatalf("Write = %d, %v", n, err)
	}

	if want := []string{"one", "two"}; !slices.Equal(got, want) {
		t.Errorf("%q made events %q, want %q: an empty line is no event", blank, got, want)
	}

	// Lines written at once, from many goroutines: every one an event of its own, whole.
	got = nil

	const writers, lines = 8, 100

	var wg sync.WaitGroup

	for g := range writers {
		wg.Go(func() {
			for i := range lines {
				_, _ = fmt.Fprintf(w, "writer %d line %d\r\n", g, i)
			}
		})
	}

	wg.Wait()

	events := make(map[string]int, len(got))
	for _, msg := range got {
		events[msg]++
	}

	for g := range writers {
		for i := range lines {
			if line := fmt.Sprintf("writer %d line %d", g, i); events[line] != 1 {
				t.Errorf("%q arrived whole %d times, want once", line, events[line])
			}
		}
	}

	if len(got) != writers*lines {
		t.Errorf("%d lines written at once made %d events", writers*lines, len(got))
	}
}
