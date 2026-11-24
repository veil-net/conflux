package cli

import (
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/flock"
	"github.com/veil-net/conflux/internal/paths"
)

// fakeManager records what it was asked and reports what the marker looked like at the
// moment Restart was called.
type fakeManager struct {
	noService

	d paths.Dirs

	restarts     int
	markedAtCall bool
}

func (m *fakeManager) Stop() error              { return nil }
func (m *fakeManager) Installed() (bool, error) { return true, nil }

func (m *fakeManager) Restart() error {
	m.restarts++
	m.markedAtCall = daemon.IsReady(m.d)

	return nil
}

func testDirs(t *testing.T) paths.Dirs {
	t.Helper()

	root := t.TempDir()
	d := paths.Dirs{Root: root}

	if err := d.EnsureAll(); err != nil {
		t.Fatalf("EnsureAll: %v", err)
	}

	return d
}

// The marker has to be gone before the restart and not after it.
//
// Reversed, waitFor could read the marker the outgoing supervisor left and return a
// status for an anchor that is seconds from being torn down -- `conflux up` reporting
// success for something on its way out. That is the one failure the ordering exists to
// prevent, and it is invisible in a diff, so it is pinned here.
func TestRestartWithClearsTheMarkerFirst(t *testing.T) {
	d := testDirs(t)

	if err := daemon.MarkReady(d, "anchorfromthepreviousrun"); err != nil {
		t.Fatalf("MarkReady: %v", err)
	}

	mgr := &fakeManager{d: d}

	if err := restartWith(d, mgr); err != nil {
		t.Fatalf("restartWith: %v", err)
	}

	if mgr.restarts != 1 {
		t.Errorf("Restart called %d times, want 1", mgr.restarts)
	}

	if mgr.markedAtCall {
		t.Error("the marker was still there when Restart was called, so waitFor could " +
			"return a status for the anchor this restart is replacing")
	}

	if daemon.IsReady(d) {
		t.Error("the marker survived restartWith")
	}
}

// Every shutdown path calls the clear, including those on a machine that has never had a
// marker, so restartWith must not fail on its absence.
func TestRestartWithWorksWithNoMarker(t *testing.T) {
	d := testDirs(t)
	mgr := &fakeManager{d: d}

	if err := restartWith(d, mgr); err != nil {
		t.Fatalf("restartWith with no marker: %v", err)
	}

	if mgr.restarts != 1 {
		t.Errorf("Restart called %d times, want 1", mgr.restarts)
	}
}

// TestBringWritesTheConfigurationUnderTheLock: the supervisor rewrites conflux.json in its
// own form as it starts, under the machine's lock, so a command's write takes the same lock
// and is never written back over by a start that read the file before it.
func TestBringWritesTheConfigurationUnderTheLock(t *testing.T) {
	d := testDirs(t)

	unlock, err := flock.Acquire(d.LockFile())
	if err != nil {
		t.Fatal(err)
	}

	saved := make(chan error, 1)

	go func() { saved <- saveConfig(d, &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}}) }()

	select {
	case err := <-saved:
		unlock()
		t.Fatalf("the configuration was written while another held the lock (%v)", err)
	case <-time.After(200 * time.Millisecond):
	}

	unlock()

	if err := <-saved; err != nil {
		t.Fatal(err)
	}

	if _, err := config.Load(d); err != nil {
		t.Errorf("no configuration was written once the lock was free: %v", err)
	}
}
