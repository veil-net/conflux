package cli

import (
	"os"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/pathstest"
)

// fakeManager records what it was asked and reports what the marker looked like at the
// moment Install and Restart were called. startsOnInstall makes its Install start the
// service, as launchd's does for a running job whose plist changed, with a supervisor that
// marks itself ready at once.
type fakeManager struct {
	d paths.Dirs

	startsOnInstall bool

	installs        [][]string
	restarts        int
	markedAtInstall bool
	markedAtCall    bool
}

func (m *fakeManager) Install(exe string, args ...string) error {
	m.installs = append(m.installs, append([]string{exe}, args...))
	m.markedAtInstall = daemon.IsReady(m.d)

	if m.startsOnInstall {
		return daemon.MarkReady(m.d, "anchorstartedbyinstall")
	}

	return nil
}

func (m *fakeManager) Remove() error            { return nil }
func (m *fakeManager) Stop() error              { return nil }
func (m *fakeManager) Installed() (bool, error) { return true, nil }
func (m *fakeManager) Describe() string         { return "fake" }
func (m *fakeManager) LogHint() string          { return "fake" }

func (m *fakeManager) Restart() error {
	m.restarts++
	m.markedAtCall = daemon.IsReady(m.d)

	return nil
}

// TestTheMarkerIsWithdrawnBeforeAnythingStarts: every path that restarts the service and
// waits for it registers it first, and the readiness marker is withdrawn before anything
// in that can start the service -- launchd's Install can -- and not after.
//
// A marker the outgoing supervisor left would otherwise let waitFor return a status for an
// anchor seconds from being torn down -- `conflux up` reporting success for something on
// its way out -- so it is gone before Install. And a marker the new supervisor writes the
// moment Install starts it is the one waitFor is waiting for, so nothing withdraws it
// after: withdrawn, waitFor would see nothing and fall back to asking status once a second.
func TestTheMarkerIsWithdrawnBeforeAnythingStarts(t *testing.T) {
	d := pathstest.Dirs(t)

	if err := daemon.MarkReady(d, "anchorfromthepreviousrun"); err != nil {
		t.Fatalf("MarkReady: %v", err)
	}

	mgr := &fakeManager{d: d, startsOnInstall: true}
	standInService(t, mgr)

	if code := install(t.Context(), d, false); code != ExitOK {
		t.Fatalf("install exited %d", code)
	}

	if err := mgr.Restart(); err != nil {
		t.Fatalf("restart: %v", err)
	}

	if mgr.markedAtInstall {
		t.Error("the outgoing supervisor's marker was still there when Install ran, which can start the service")
	}

	if b, _ := os.ReadFile(d.ReadyFile()); !strings.Contains(string(b), "anchorstartedbyinstall") {
		t.Errorf("the marker the supervisor Install started wrote is gone (%q), so waitFor would fall back to status", b)
	}
}
