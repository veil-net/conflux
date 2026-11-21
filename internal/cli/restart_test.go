package cli

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/pathstest"
)

// fakeManager records what it was asked and reports what the marker looked like at the
// moment Install and Restart were called. startsOnInstall makes its Install start the
// service, as launchd's does for a running job whose plist changed, with a supervisor that
// marks itself ready at once. restartErr is what Restart answers: a stand-in that starts
// nothing, so nothing waits for what it started.
type fakeManager struct {
	d paths.Dirs

	startsOnInstall bool
	restartErr      error

	installs        [][]string
	restarts        int
	markedAtInstall bool
	markedAtRestart bool
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
	m.markedAtRestart = daemon.IsReady(m.d)

	return m.restartErr
}

// errStartsNothing is the stand-in service manager's answer to Restart.
var errStartsNothing = errors.New("the stand-in service manager starts nothing")

// TestTheMarkerIsWithdrawnBeforeAnythingStarts: every command that restarts the service and
// waits for it -- start, and up, proxy and observe, whose shared tail proxy drives here --
// registers it first, and the readiness marker is withdrawn before anything in that can
// start the service -- launchd's Install can -- and not after.
//
// A marker the outgoing supervisor left would otherwise let waitFor return a status for an
// anchor seconds from being torn down -- `conflux up` reporting success for something on
// its way out -- so it is gone before Install. And a marker the new supervisor writes the
// moment Install starts it is the one waitFor is waiting for, so nothing withdraws it
// after: withdrawn, waitFor would see nothing and fall back to asking status once a second.
func TestTheMarkerIsWithdrawnBeforeAnythingStarts(t *testing.T) {
	rootOnLinux(t)

	for name, args := range map[string][]string{
		"start": {"start"},
		"proxy": {"proxy", "8080=127.0.0.1:3000", "--taint", "t", "--no-ipv4"},
	} {
		t.Run(name, func(t *testing.T) {
			if name == "start" {
				anchortest.Require(t) // it extracts the pair afresh, as the service's copy is not this conflux
			}

			d := pathstest.Dirs(t)

			// What start starts; proxy writes its own over it.
			cfg := &config.Config{Mode: config.ModeProxy, Proxies: []string{"8080=127.0.0.1:3000"}, Taints: []string{"t"}}
			if err := config.Save(d, cfg); err != nil {
				t.Fatal(err)
			}

			if err := daemon.MarkReady(d, "anchorfromthepreviousrun"); err != nil {
				t.Fatalf("MarkReady: %v", err)
			}

			mgr := &fakeManager{d: d, startsOnInstall: true, restartErr: errStartsNothing}
			standInService(t, mgr)

			if _, errOut, code := capture(t, args...); code != ExitError || !strings.Contains(errOut, errStartsNothing.Error()) {
				t.Fatalf("conflux %s exited %d, saying:\n%s\nwant the stand-in's Restart refused", name, code, errOut)
			}

			if len(mgr.installs) != 1 || mgr.restarts != 1 {
				t.Fatalf("the stand-in was registered with %d times and restarted %d times, want once each", len(mgr.installs), mgr.restarts)
			}

			if mgr.markedAtInstall {
				t.Error("the outgoing supervisor's marker was still there when Install ran, which can start the service")
			}

			if !mgr.markedAtRestart {
				t.Error("the marker the supervisor Install started wrote was gone by Restart, so waitFor would fall back to status")
			}
		})
	}
}

// modeAtInstall is the stand-in service manager, noting the mode of dir as Install is asked.
type modeAtInstall struct {
	*fakeManager

	dir  string
	mode os.FileMode
}

func (m *modeAtInstall) Install(exe string, args ...string) error {
	if fi, err := os.Stat(m.dir); err == nil {
		m.mode = fi.Mode().Perm()
	}

	return m.fakeManager.Install(exe, args...)
}

// TestStartSecuresTheRootFirst: start is how update hands a running service to the conflux it put in
// place, so it makes the root conflux's, as the service does at every start (EnsureAll), before it
// reads the configuration there, places conflux in it or registers the service: a root of conflux's
// left wider than conflux leaves one is narrowed by the time the service is registered, and a
// configuration that is a link -- to a file of garbage -- is refused as the link it is, not read
// through it and refused as garbage. On Windows, where a mode means nothing, what it gives the
// Administrators is held by its own test.
func TestStartSecuresTheRootFirst(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a mode means nothing on Windows")
	}

	rootOnLinux(t)

	t.Run("a root left wider", func(t *testing.T) {
		anchortest.Require(t) // it extracts the pair afresh, as the service's copy is not this conflux

		d := pathstest.Dirs(t)

		if err := config.Save(d, &config.Config{Mode: config.ModeProxy, Proxies: []string{"8080=127.0.0.1:3000"},
			Taints: []string{"t"}}); err != nil {
			t.Fatal(err)
		}

		if err := os.Chmod(d.State, 0o755); err != nil {
			t.Fatal(err)
		}

		mgr := &modeAtInstall{fakeManager: &fakeManager{d: d, restartErr: errStartsNothing}, dir: d.State}
		standInService(t, mgr)

		if _, errOut, code := capture(t, "start"); code != ExitError || !strings.Contains(errOut, errStartsNothing.Error()) {
			t.Fatalf("conflux start exited %d, saying:\n%s\nwant the stand-in's Restart refused", code, errOut)
		}

		if len(mgr.installs) != 1 || mgr.mode != 0o700 {
			t.Errorf("start registered the service %d times, with the root at %#o, want once, at 0700", len(mgr.installs),
				mgr.mode)
		}
	})

	t.Run("a configuration that is a link", func(t *testing.T) {
		d := pathstest.Dirs(t)

		garbage := filepath.Join(t.TempDir(), "garbage")
		if err := os.WriteFile(garbage, []byte("{not a configuration"), 0o600); err != nil {
			t.Fatal(err)
		}

		if err := os.Symlink(garbage, d.ConfigFile()); err != nil {
			t.Fatal(err)
		}

		mgr := &fakeManager{d: d, restartErr: errStartsNothing}
		standInService(t, mgr)

		_, errOut, code := capture(t, "start")
		if code != ExitError || !strings.Contains(errOut, d.ConfigFile()+", a link") {
			t.Errorf("conflux start of a root whose configuration is a link exited %d, saying:\n%s\nwant the link "+
				"refused by name, not the file it leads to read", code, errOut)
		}

		if len(mgr.installs)+mgr.restarts > 0 {
			t.Errorf("start registered the service %d times and restarted it %d", len(mgr.installs), mgr.restarts)
		}
	})
}
