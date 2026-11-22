package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/flock"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/pathstest"
	"github.com/veil-net/conflux/internal/privcheck"
	"github.com/veil-net/conflux/internal/service"
)

// earlier is an installation as earlier conflux left it (oldInstall).
type earlier struct {
	d paths.Dirs

	// kept is what an update keeps, by path: the configuration, the identity and the state.
	kept map[string][]byte

	// exe is the conflux an update replaced, and leftovers and besideKept what is beside it, which
	// conflux removes as what an update left, and keeps (updatedConflux).
	exe                   string
	leftovers, besideKept []string

	// temporary is the folder a reader killed before it removed its temporary anchorctl left.
	temporary string
}

// oldInstall is a CONFLUX_DIR installation as earlier conflux left it, for an update or an uninstall
// to find: the configuration, the identity and the state with a given-up record in it, and what an
// update does not keep -- a set an earlier conflux extracted, a staging directory a crashed extraction
// left, this build's own set planted by somebody, its binaries padded to their sizes, stale lock
// files, an older copy for the service with the image Windows moved aside and a copy that never went
// in place, an atomic write that never went in place, the run directory's token, marker, pid record
// and socket directory, a killed ephemeral run's root, a killed reader's temporary anchorctl in the
// temporary directory, which is the test's own, and beside the conflux the update replaced what an update
// leaves there (updatedConflux).
func oldInstall(t *testing.T) earlier {
	t.Helper()

	d := pathstest.Dirs(t)

	tmp := pathstest.Temporary(t, t.TempDir())

	if err := config.Save(d, &config.Config{Mode: config.ModeProxy, Proxies: []string{"8080=127.0.0.1:3000"},
		Taints: []string{"cfx-old"}}); err != nil {
		t.Fatal(err)
	}

	if err := config.SaveManifest(d, config.Envelope("bWFuaWZlc3Q=")); err != nil {
		t.Fatal(err)
	}

	if err := config.SaveState(d, &config.State{AnchorID: "anchorold", IssuedAt: time.Now().Add(-time.Hour),
		AnchorRefused: "refused for good", AnchorRefusedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	set := filepath.Join(d.Libexec(), anchor.SetID())
	old := earlier{d: d, kept: map[string][]byte{}, temporary: filepath.Join(tmp, "conflux-usage-123")}
	old.exe, old.leftovers, old.besideKept = updatedConflux(t)

	for p, body := range map[string][]byte{
		filepath.Join(d.Libexec(), "0123456789abcdef", binName("anchord")): []byte("an earlier set"),
		filepath.Join(d.Libexec(), ".staging-123", binName("anchord")):     []byte("a crashed extraction"),
		filepath.Join(set, binName("anchord")):                             make([]byte, len(anchor.Anchord())),
		filepath.Join(set, binName("anchorctl")):                           make([]byte, len(anchor.Anchorctl())),
		filepath.Join(d.Libexec(), ".lock"):                                []byte("stale"),
		d.LockFile():                                                       []byte("stale"),
		d.ServeLockFile():                                                  []byte("stale"),
		d.ServiceExecutable():                                              []byte("an earlier conflux"),
		d.ServiceExecutable() + ".old":                                     []byte("an earlier conflux still"),
		filepath.Join(d.State, ".conflux-123"):                             []byte("a copy that never went in place"),
		filepath.Join(d.State, ".tmp-123"):                                 []byte("a write that never went in place"),
		d.TokenFile():                                                      []byte("token"),
		d.ReadyFile():                                                      []byte("ready"),
		d.DaemonPIDFile():                                                  []byte("2147483646\n/nonexistent/anchord\n"),
		filepath.Join(d.DaemonRun(), "sock.lock"):                          nil,
		filepath.Join(paths.EphemeralCandidates()[0], "serve.lock"):        nil,
		filepath.Join(old.temporary, binName("anchorctl")):                 []byte("a killed reader's"),
	} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	for _, p := range []string{d.ConfigFile(), d.ManifestFile(), d.StateFile()} {
		old.kept[p] = mustRead(t, p)
	}

	return old
}

// TestUpdateLeavesOnlyWhatThisConfluxMakes: update hands the service to the conflux it put in place
// through that conflux's register, the anchor stopped, or its start, the anchor running; a conflux put
// in place by hand, or by an install script, reaches the service through its install, as through up,
// proxy and observe, which share it; and before any of them places or registers anything, it removes
// what earlier conflux left everywhere conflux keeps files, and makes what it removed afresh. What is left is this conflux's alone: this build's set,
// extracted again over the one planted padded to its sizes; no other set, nothing staged; a copy for
// the service that is this conflux, nothing beside it, nor a write that never went in place; an empty
// run directory; no killed run's root; nothing an update left beside the conflux it replaced. The
// configuration, the identity and the state are as they were, and so, on Unix, are the lock files,
// which Windows makes again (locksKeptOrRemade).
func TestUpdateLeavesOnlyWhatThisConfluxMakes(t *testing.T) {
	anchortest.Require(t)

	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	for _, verb := range []string{"register", "start", "install"} {
		t.Run(verb, func(t *testing.T) {
			old := oldInstall(t)
			d := old.d

			mgr := &fakeManager{d: d, restartErr: errStartsNothing}
			standInService(t, mgr)

			out, errOut, code := capture(t, verb)

			want, restarts := ExitOK, 0
			if verb != "register" {
				want, restarts = ExitError, 1
			}

			if code != want || len(mgr.installs) != 1 || mgr.restarts != restarts {
				t.Fatalf("conflux %s exited %d, registered %d times and restarted %d, want %d, once and %d:\n%s%s",
					verb, code, len(mgr.installs), mgr.restarts, want, restarts, out, errOut)
			}

			set := filepath.Join(d.Libexec(), anchor.SetID())

			if got := names(t, d.Libexec()); !slices.Equal(got, []string{".lock", anchor.SetID()}) {
				t.Errorf("%s holds %q, want this build's set and its lock alone", d.Libexec(), got)
			}

			for p, want := range map[string][]byte{
				filepath.Join(set, binName("anchord")):   anchor.Anchord(),
				filepath.Join(set, binName("anchorctl")): anchor.Anchorctl(),
			} {
				if b, err := os.ReadFile(p); err != nil || !bytes.Equal(b, want) {
					t.Errorf("%s is not what this conflux makes (%d bytes, %v)", p, len(b), err)
				}
			}

			locksKeptOrRemade(t, d)

			this, err := service.Executable()
			if err != nil {
				t.Fatal(err)
			}

			if b, _ := os.ReadFile(d.ServiceExecutable()); !bytes.Equal(b, mustRead(t, this)) {
				t.Errorf("%s is not this conflux", d.ServiceExecutable())
			}

			gone := append([]string{d.ServiceExecutable() + ".old", filepath.Join(d.State, ".conflux-123"),
				filepath.Join(d.State, ".tmp-123"), paths.EphemeralCandidates()[0]}, old.leftovers...)

			for _, p := range gone {
				if _, err := os.Lstat(p); !os.IsNotExist(err) {
					t.Errorf("%s is still there (Lstat: %v)", p, err)
				}
			}

			if _, err := os.Lstat(old.temporary); !os.IsNotExist(err) || !strings.Contains(out, "  "+old.temporary+"\n") {
				t.Errorf("conflux %s left %s, a killed reader's temporary anchorctl (Lstat: %v), or did not list it:\n%s",
					verb, old.temporary, err, out)
			}

			if got := names(t, d.Run); len(got) > 0 {
				t.Errorf("%s holds %q, which the supervisors before this conflux left", d.Run, got)
			}

			for p, was := range old.kept {
				if b, err := os.ReadFile(p); err != nil || !bytes.Equal(b, was) {
					t.Errorf("%s changed: %q, %v", p, b, err)
				}
			}

			for _, p := range old.besideKept {
				if _, err := os.Lstat(p); err != nil {
					t.Errorf("conflux %s removed %s, which no update of it left there: %v", verb, p, err)
				}
			}

			if !strings.Contains(out, "Removed what earlier conflux left:") {
				t.Errorf("conflux %s did not say what it removed:\n%s", verb, out)
			}

			// This build's set is extracted again, and so is not gone.
			if strings.Contains(out, "  "+set) {
				t.Errorf("conflux %s listed %s, which it extracted again, as removed:\n%s", verb, set, out)
			}
		})
	}
}

// TestAStartOfTheConfluxTheServiceRunsRemovesNothing: a start of the conflux the service already
// runs is no update, and leaves alone what is there, as every start before it did.
func TestAStartOfTheConfluxTheServiceRunsRemovesNothing(t *testing.T) {
	anchortest.Require(t)

	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	old := oldInstall(t)
	d := old.d

	if _, err := service.PlaceAfresh(d); err != nil {
		t.Fatal(err)
	}

	mgr := &fakeManager{d: d, restartErr: errStartsNothing}
	standInService(t, mgr)

	if _, errOut, code := capture(t, "start"); code != ExitError || mgr.restarts != 1 {
		t.Fatalf("conflux start exited %d and restarted %d times:\n%s", code, mgr.restarts, errOut)
	}

	for _, p := range append(append([]string{filepath.Join(d.Libexec(), "0123456789abcdef"), d.LockFile()},
		old.leftovers...), old.besideKept...) {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("a start of the conflux the service runs removed %s: %v", p, err)
		}
	}
}

// TestACopyNotAsConfluxMakesItIsPlacedAfresh: a copy for the boot service that is this conflux, byte for
// byte, but is not as conflux makes a file of its own (pathstest.NotAsConfluxMakesIt) -- as an earlier conflux left
// one on a Windows client, an administrator's, which that administrator's unelevated processes could
// change for SYSTEM to run -- is what earlier conflux left: the supervisor, which runs from it, leaves it
// as it makes its roots (EnsureServing), placing it afresh after, and start and install remove it with
// the rest (tidy), an earlier set among it, and place this conflux afresh, as conflux makes it, and
// register that.
func TestACopyNotAsConfluxMakesItIsPlacedAfresh(t *testing.T) {
	anchortest.Require(t) // it extracts the pair afresh

	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	for _, verb := range []string{"start", "install"} {
		t.Run(verb, func(t *testing.T) {
			d := configured(t)

			if _, err := service.PlaceAfresh(d); err != nil {
				t.Fatal(err)
			}

			pathstest.NotAsConfluxMakesIt(t, d.ServiceExecutable())

			if err := d.EnsureServing(); err != nil {
				t.Fatal(err)
			}

			if err := d.Ours(d.ServiceExecutable()); err == nil || errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("the supervisor's making of the roots changed the copy it runs from: %v", err)
			}

			earlier := filepath.Join(d.Libexec(), "0123456789abcdef")
			if err := os.MkdirAll(earlier, 0o700); err != nil {
				t.Fatal(err)
			}

			mgr := &fakeManager{d: d, restartErr: errStartsNothing}
			standInService(t, mgr)

			out, errOut, _ := capture(t, verb)

			if err := d.Ours(d.ServiceExecutable()); err != nil || len(mgr.installs) != 1 {
				t.Errorf("conflux %s of a copy not as conflux makes it left the copy %v, and registered %d times, "+
					"want it placed afresh and registered once:\n%s%s", verb, err, len(mgr.installs), out, errOut)
			}

			if _, err := os.Lstat(earlier); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("conflux %s of a copy not as conflux makes it left what earlier conflux left (Lstat %s: %v)",
					verb, earlier, err)
			}
		})
	}
}

// oursAtRestart is stopping, which records at each Restart what paths' Ours says of the copy of conflux
// the service runs.
type oursAtRestart struct {
	stopping

	ours []error
}

func (m *oursAtRestart) Restart() error {
	m.ours = append(m.ours, m.d.Ours(m.d.ServiceExecutable()))

	return m.stopping.Restart()
}

// TestTheServiceStartsAgainOnlyOnACopyOfConfluxsOwn: the service tidy stopped is never started again on a
// copy of conflux that is not as conflux makes a file of its own: where tidy fails once EnsureAll has
// removed one -- here at bin's lock, a folder at its name, which nothing can take -- this conflux is
// placed afresh before the service is started again, once, and the command's failure kept.
func TestTheServiceStartsAgainOnlyOnACopyOfConfluxsOwn(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	d := configured(t)

	if _, err := service.PlaceAfresh(d); err != nil {
		t.Fatal(err)
	}

	pathstest.NotAsConfluxMakesIt(t, d.ServiceExecutable())

	if err := os.MkdirAll(filepath.Join(d.Libexec(), ".lock"), 0o700); err != nil {
		t.Fatal(err)
	}

	// The restart starts nothing, so a conflux that went on to wait for the anchor stops there.
	mgr := &oursAtRestart{stopping: stopping{fakeManager: fakeManager{d: d, restartErr: errStartsNothing}, running: true,
		release: serving(t, d)}}
	standInService(t, mgr)

	out, errOut, code := capture(t, "start")
	if code != ExitError || mgr.stops != 1 || len(mgr.ours) != 1 || mgr.ours[0] != nil {
		t.Errorf("conflux start, failing once it stopped the service, exited %d, stopped it %d times and started it "+
			"again on copies Ours said %v of, want %d, once each, on a copy of conflux's own:\n%s%s", code, mgr.stops,
			mgr.ours, ExitError, out, errOut)
	}
}

// TestTheCopyIsPlacedOnceIntoAFreshInstallation: up into a CONFLUX_DIR with nothing of conflux's in it
// places this conflux as the boot service's copy, and registers that; up again, install and start, each
// finding the copy there and this conflux, keep that same file, writing nothing. (proxy in up's place
// on Windows, where up fetches wintun first.)
func TestTheCopyIsPlacedOnceIntoAFreshInstallation(t *testing.T) {
	rootOnLinux(t)

	t.Setenv("CONFLUX_DIR", t.TempDir())

	d := paths.Default()

	mgr := &fakeManager{d: d, restartErr: errStartsNothing}
	standInService(t, mgr)

	first := []string{"up", "--taint", "t", "--no-ipv4"}
	if runtime.GOOS == "windows" {
		first = []string{"proxy", "8080=127.0.0.1:3000", "--taint", "t", "--no-ipv4"}
	}

	out, errOut, _ := capture(t, first...)

	placed, err := os.Stat(d.ServiceExecutable())
	if err != nil || !service.Placed(d) || len(mgr.installs) != 1 || mgr.installs[0][0] != d.ServiceExecutable() {
		t.Fatalf("conflux %s into a fresh CONFLUX_DIR left the copy %v (Placed: %v) and registered %q, want this "+
			"conflux placed and registered:\n%s%s", first[0], err, service.Placed(d), mgr.installs, out, errOut)
	}

	for _, args := range [][]string{first, {"install"}, {"start"}} {
		out, errOut, _ := capture(t, args...)

		if again, err := os.Stat(d.ServiceExecutable()); err != nil || !os.SameFile(placed, again) {
			t.Errorf("conflux %s, the copy this conflux already, wrote it again (%v):\n%s%s", args[0], err, out, errOut)
		}
	}
}

// locksKeptOrRemade fails t unless the lock files oldInstall left in d, each holding "stale", are as
// tidy leaves them: on Unix kept, the same files, since a lock taken on a file removed meanwhile is
// one nobody else finds, so two would hold it; on Windows, which removes no file anybody has open,
// none is the earlier conflux's still -- bin's made again, empty, and the other two gone or made so.
func locksKeptOrRemade(t *testing.T, d paths.Dirs) {
	t.Helper()

	binLock := filepath.Join(d.Libexec(), ".lock")

	for _, p := range []string{binLock, d.LockFile(), d.ServeLockFile()} {
		b, err := os.ReadFile(p)

		switch {
		case runtime.GOOS != "windows":
			if err != nil || string(b) != "stale" {
				t.Errorf("%s was not kept: %q, %v", p, b, err)
			}
		case p == binLock && (err != nil || len(b) > 0):
			t.Errorf("%s is not the lock this conflux makes (%q, %v)", p, b, err)
		case err == nil && len(b) > 0:
			t.Errorf("%s is the earlier conflux's still, holding %q", p, b)
		}
	}
}

// names is what dir holds, by name, in order; none where it is not there.
func names(t *testing.T, dir string) []string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}

	var found []string
	for _, e := range entries {
		found = append(found, e.Name())
	}

	return found
}

// binName is an extracted binary's name on this platform.
func binName(base string) string {
	if runtime.GOOS == "windows" {
		return base + ".exe"
	}

	return base
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	return b
}

// stopping is the stand-in service manager for a supervisor serving the root, holding its serve
// lock: running is what it says of the service, or unanswered why it cannot say, and asked, it does
// asked first, where it is given that; Stop counts, and lets go of that lock where it is given
// release, as a supervisor stopping does.
type stopping struct {
	fakeManager

	running    bool
	unanswered error
	asked      func()
	release    func()
	stops      int
}

func (m *stopping) Running() (bool, error) {
	if m.asked != nil {
		m.asked()
	}

	return m.running, m.unanswered
}

func (m *stopping) Stop() error {
	m.stops++

	if m.release != nil {
		m.release()
		m.release = nil
	}

	return nil
}

// serving holds d's serve lock, as a supervisor serving the root does, until the test ends or the
// function it returns is called, whichever is first.
func serving(t *testing.T, d paths.Dirs) func() {
	t.Helper()

	unlock, err := flock.Acquire(d.ServeLockFile())
	if err != nil {
		t.Fatal(err)
	}

	var once sync.Once

	release := func() { once.Do(unlock) }
	t.Cleanup(release)

	return release
}

// configured is a CONFLUX_DIR installation with a configuration to start, and nothing else.
func configured(t *testing.T) paths.Dirs {
	t.Helper()

	d := pathstest.Dirs(t)

	if err := config.Save(d, &config.Config{Mode: config.ModeProxy, Proxies: []string{"8080=127.0.0.1:3000"},
		Taints: []string{"t"}}); err != nil {
		t.Fatal(err)
	}

	return d
}

// TestTidyStartsAgainTheServiceItStopped: where a supervisor serves the root, the conflux an update
// put in place stops the service before it removes what earlier conflux left, and starts it again
// once it is done, on itself: register, which starts nothing it did not stop, restarts it; start, and
// install, of a conflux put in place by hand, restart it as every start does.
func TestTidyStartsAgainTheServiceItStopped(t *testing.T) {
	anchortest.Require(t) // it extracts the pair afresh

	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	for _, verb := range []string{"register", "start", "install"} {
		t.Run(verb, func(t *testing.T) {
			d := configured(t)

			mgr := &stopping{fakeManager: fakeManager{d: d}, running: true, release: serving(t, d)}
			standInService(t, mgr)

			want := ExitOK
			if verb != "register" {
				mgr.restartErr, want = errStartsNothing, ExitError
			}

			out, errOut, code := capture(t, verb)

			if code != want || mgr.stops != 1 || len(mgr.installs) != 1 || mgr.restarts != 1 {
				t.Errorf("conflux %s of a root a supervisor serves exited %d, stopped the service %d times, "+
					"registered it %d and started it %d, want %d, once each:\n%s%s", verb, code, mgr.stops,
					len(mgr.installs), mgr.restarts, want, out, errOut)
			}
		})
	}
}

// TestTidyStartsAgainHoweverTheCommandEnds: the service tidy stopped is started again however the
// command it stopped it for ends, and the command's code is kept: start refusing a configuration it
// cannot read, finding none, or failing to register the service. A failure to start it fails a command
// that had not failed -- register, which registered the service -- and is warned of beside one that
// had.
func TestTidyStartsAgainHoweverTheCommandEnds(t *testing.T) {
	anchortest.Require(t) // it extracts the pair afresh

	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	errRegister := errors.New("the stand-in service manager registers nothing")

	unreadable := func(t *testing.T, d paths.Dirs, _ *stopping) {
		if err := os.WriteFile(d.ConfigFile(), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	unconfigured := func(t *testing.T, d paths.Dirs, _ *stopping) {
		if err := os.Remove(d.ConfigFile()); err != nil {
			t.Fatal(err)
		}
	}

	for name, c := range map[string]struct {
		verb    string
		then    func(*testing.T, paths.Dirs, *stopping)
		restart error
		want    int
		says    string
	}{
		"start, a configuration it cannot read": {verb: "start", then: unreadable, want: ExitError, says: "parse "},
		"start, no configuration": {verb: "start", then: unconfigured, want: ExitNoConfig,
			says: "no configuration"},
		"start, registering failing": {verb: "start", then: func(_ *testing.T, _ paths.Dirs, m *stopping) {
			m.installErr = errRegister
		}, want: ExitError, says: errRegister.Error()},
		"register, starting again failing": {verb: "register", restart: errStartsNothing, want: ExitError,
			says: errStartsNothing.Error()},
		"start, no configuration, starting again failing": {verb: "start", then: unconfigured,
			restart: errStartsNothing, want: ExitNoConfig, says: "did not start again: " + errStartsNothing.Error()},
	} {
		t.Run(name, func(t *testing.T) {
			d := configured(t)

			mgr := &stopping{fakeManager: fakeManager{d: d, restartErr: c.restart}, running: true,
				release: serving(t, d)}
			standInService(t, mgr)

			if c.then != nil {
				c.then(t, d, mgr)
			}

			out, errOut, code := capture(t, c.verb)
			if code != c.want || mgr.stops != 1 || mgr.restarts != 1 || !strings.Contains(errOut, c.says) {
				t.Errorf("conflux %s exited %d, stopped the service %d times and started it %d, want %d, once each, "+
					"saying %q:\n%s%s", c.verb, code, mgr.stops, mgr.restarts, c.want, c.says, out, errOut)
			}
		})
	}
}

// TestAnUpgradeStartsAgainTheServiceItStopped: up, proxy, observe, install and start, of a conflux put in
// place by hand, stop the service before they make its roots afresh, and start it again once however they
// end: by their own restart where they get that far, which failing is not tried again, though the
// service manager says the service is down after it, as systemd and launchd say of a start that failed;
// and otherwise as they exit -- here refusing a configuration they cannot read -- their code kept. enrol,
// which restarts nothing itself, starts it again once as it exits. (up only off Windows, where it fetches
// wintun first.)
func TestAnUpgradeStartsAgainTheServiceItStopped(t *testing.T) {
	anchortest.Require(t) // it extracts the pair afresh

	rootOnLinux(t)

	commands := map[string][]string{
		"proxy":   {"proxy", "8080=127.0.0.1:3000", "--taint", "t", "--no-ipv4"},
		"observe": {"observe", "--yes"},
		"install": {"install"},
		"start":   {"start"},
	}

	if runtime.GOOS != "windows" {
		commands["up"] = []string{"up", "--taint", "t", "--no-ipv4"}
	}

	unreadable := func(t *testing.T, d paths.Dirs) {
		if err := os.WriteFile(d.ConfigFile(), []byte("{"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	type upgrade struct {
		args []string
		then func(*testing.T, paths.Dirs)
		says string
	}

	cases := map[string]upgrade{
		"enrol, a manifest that is not there": {args: []string{"enrol", "--manifest", filepath.Join(t.TempDir(),
			"missing")}, says: "missing"},
	}

	for verb, args := range commands {
		cases[verb+", its own restart failing"] = upgrade{args: args, says: errStartsNothing.Error()}
		cases[verb+", a configuration it cannot read"] = upgrade{args: args, then: unreadable, says: "parse "}
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			d := configured(t)

			if c.then != nil {
				c.then(t, d)
			}

			mgr := &downOnceStopped{stopping{fakeManager: fakeManager{d: d, restartErr: errStartsNothing}, running: true,
				release: serving(t, d)}}
			standInService(t, mgr)

			out, errOut, code := capture(t, c.args...)
			if code != ExitError || mgr.stops != 1 || mgr.restarts != 1 || !strings.Contains(errOut, c.says) {
				t.Errorf("conflux %s of an upgraded installation exited %d, stopped the service %d times and started "+
					"it %d, want %d, once each, saying %q:\n%s%s", c.args[0], code, mgr.stops, mgr.restarts, ExitError,
					c.says, out, errOut)
			}
		})
	}
}

// downOnceStopped is stopping whose service the service manager says runs until it is stopped, and not
// after, a start that failed among it.
type downOnceStopped struct{ stopping }

func (m *downOnceStopped) Running() (bool, error) {
	running, err := m.stopping.Running()

	return running && m.stops == 0, err
}

// TestTidyStartsNothingBesideASupervisorRunByHand: a supervisor that serves the root once the boot
// service is stopped, or that serves it with no service running, is one the boot service did not start
// -- one run by hand -- which leaves what earlier conflux left in use: the update is refused, naming
// it, with nothing removed or registered, and nothing is started, since a service started beside it
// would find it there and exit. A service the service manager says is not running is not stopped.
func TestTidyStartsNothingBesideASupervisorRunByHand(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	for _, verb := range []string{"register", "start"} {
		for _, running := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/running=%v", verb, running), func(t *testing.T) {
				d := configured(t)
				serving(t, d)

				mgr := &stopping{fakeManager: fakeManager{d: d}, running: running}
				standInService(t, mgr)

				out, errOut, code := capture(t, verb)

				if code != ExitError || !strings.Contains(errOut, d.State) || !strings.Contains(errOut, "run by hand") {
					t.Errorf("conflux %s beside a supervisor run by hand exited %d, want %d naming it:\n%s%s",
						verb, code, ExitError, out, errOut)
				}

				stops := 0
				if running {
					stops = 1
				}

				if mgr.stops != stops || len(mgr.installs) != 0 || mgr.restarts != 0 {
					t.Errorf("conflux %s stopped the service %d times, registered it %d and started it %d, "+
						"want it stopped %d times, and nothing registered or started", verb, mgr.stops,
						len(mgr.installs), mgr.restarts, stops)
				}
			})
		}
	}
}

// TestTidyStartsNothingBesideASupervisorThatTookTheRoot: a supervisor that starts serving the root
// once tidy has stopped the boot service -- here as tidy makes the roots -- is no service tidy
// stopped either: the update is refused, exit 1, naming the root, with nothing registered and nothing
// started, the service tidy stopped included, since started beside that supervisor it would find it
// there and exit.
func TestTidyStartsNothingBesideASupervisorThatTookTheRoot(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	for _, verb := range []string{"register", "start"} {
		t.Run(verb, func(t *testing.T) {
			d := configured(t)

			mgr := &stopping{fakeManager: fakeManager{d: d}, running: true, release: serving(t, d)}
			standInService(t, mgr)

			was := ensureAll
			defer func() { ensureAll = was }()

			ensureAll = func(d paths.Dirs) error {
				err := was(d)
				serving(t, d)

				return err
			}

			out, errOut, code := capture(t, verb)
			if code != ExitError || !strings.Contains(errOut, "started serving "+d.State) {
				t.Errorf("conflux %s beside a supervisor that took the root once the service was stopped exited %d, "+
					"want %d naming it:\n%s%s", verb, code, ExitError, out, errOut)
			}

			if mgr.stops != 1 || len(mgr.installs) != 0 || mgr.restarts != 0 {
				t.Errorf("conflux %s stopped the service %d times, registered it %d and started it %d, want it "+
					"stopped once, and nothing registered or started", verb, mgr.stops, len(mgr.installs), mgr.restarts)
			}
		})
	}
}

// TestTidyStartsAgainWhatItStoppedWhereTheLockCannotBeAsked: where the serve lock cannot be asked
// after once the boot service is stopped -- here no plain file is at its name any more -- which
// supervisor serves the root cannot be told, and the update is refused, exit 1, saying why, with
// nothing registered; and the service tidy stopped is started again, as it was found.
func TestTidyStartsAgainWhatItStoppedWhereTheLockCannotBeAsked(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	for _, verb := range []string{"register", "start"} {
		t.Run(verb, func(t *testing.T) {
			d := configured(t)
			release := serving(t, d)

			mgr := &stopping{fakeManager: fakeManager{d: d}, running: true, release: func() {
				release()

				if err := os.Remove(d.ServeLockFile()); err != nil {
					t.Error(err)
				}

				if err := os.Mkdir(d.ServeLockFile(), 0o700); err != nil {
					t.Error(err)
				}
			}}
			standInService(t, mgr)

			out, errOut, code := capture(t, verb)
			if code != ExitError || !strings.Contains(errOut, d.ServeLockFile()) || strings.Contains(errOut, "run by hand") {
				t.Errorf("conflux %s with the serve lock unaskable once the service was stopped exited %d, want %d "+
					"naming the lock, not a supervisor run by hand:\n%s%s", verb, code, ExitError, out, errOut)
			}

			if mgr.stops != 1 || len(mgr.installs) != 0 || mgr.restarts != 1 {
				t.Errorf("conflux %s stopped the service %d times, registered it %d and started it %d, want it "+
					"stopped and started again once each, and nothing registered", verb, mgr.stops,
					len(mgr.installs), mgr.restarts)
			}
		})
	}
}

// TestTidyStopsNothingWhereTheServiceManagerDoesNotAnswer: where the service manager cannot say
// whether the boot service runs, tidy cannot tell the supervisor serving the root for the service's or
// one run by hand, so the update is refused, saying the service manager did not answer and why, not
// that a supervisor was run by hand, with nothing stopped, registered or started.
func TestTidyStopsNothingWhereTheServiceManagerDoesNotAnswer(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	unanswered := errors.New("the stand-in service manager does not answer")

	for _, verb := range []string{"register", "start"} {
		t.Run(verb, func(t *testing.T) {
			d := configured(t)

			mgr := &stopping{fakeManager: fakeManager{d: d}, running: true, unanswered: unanswered,
				release: serving(t, d)}
			standInService(t, mgr)

			out, errOut, code := capture(t, verb)
			if code != ExitError || !strings.Contains(errOut, unanswered.Error()) || strings.Contains(errOut, "run by hand") {
				t.Errorf("conflux %s with the service manager not answering exited %d, want %d saying why, not that a "+
					"supervisor was run by hand:\n%s%s", verb, code, ExitError, out, errOut)
			}

			if mgr.stops+len(mgr.installs)+mgr.restarts > 0 {
				t.Errorf("conflux %s stopped the service %d times, registered it %d and started it %d, want none",
					verb, mgr.stops, len(mgr.installs), mgr.restarts)
			}
		})
	}
}

// TestTidyStartsAgainOnlyWhatItStopped: a supervisor serving the root that the service manager says
// is not the boot service's -- one run by hand, gone as it is asked -- is not stopped, and the boot
// service is not started after: register, which starts nothing it did not stop, starts nothing.
func TestTidyStartsAgainOnlyWhatItStopped(t *testing.T) {
	anchortest.Require(t) // it extracts the pair afresh

	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	d := configured(t)

	mgr := &stopping{fakeManager: fakeManager{d: d}, asked: serving(t, d)}
	standInService(t, mgr)

	out, errOut, code := capture(t, "register")
	if code != ExitOK || mgr.stops != 0 || len(mgr.installs) != 1 || mgr.restarts != 0 {
		t.Errorf("conflux register beside a supervisor gone as the service manager was asked exited %d, stopped "+
			"the service %d times, registered it %d and started it %d, want %d, registered once and nothing "+
			"else:\n%s%s", code, mgr.stops, len(mgr.installs), mgr.restarts, ExitOK, out, errOut)
	}
}

// TestTidyListsOnlyWhatItRemoved: what tidy says it removed is what is gone. Where bin cannot be emptied
// -- its lock a folder, which nothing can take -- the earlier sets in bin are not removed, nor listed, and
// the update is refused, since a set planted among them would be kept; what it could not remove of the run
// directory, which the next supervisor makes again, it warns of and goes on, listing what went; and a
// killed ephemeral run's root that a run takes the moment its lock is let go of is that run's, kept,
// and not listed.
func TestTidyListsOnlyWhatItRemoved(t *testing.T) {
	anchortest.Require(t) // it extracts the pair afresh

	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	t.Run("bin's lock a folder", func(t *testing.T) {
		d := configured(t)

		earlier := filepath.Join(d.Libexec(), "0123456789abcdef")
		lock := filepath.Join(d.Libexec(), ".lock")

		for _, p := range []string{earlier, lock} {
			if err := os.MkdirAll(p, 0o700); err != nil {
				t.Fatal(err)
			}
		}

		standInService(t, &fakeManager{d: d})

		out, errOut, code := capture(t, "register")
		if code != ExitError || !strings.Contains(errOut, lock) {
			t.Errorf("conflux register with a folder at bin's lock exited %d, want %d saying why:\n%s%s", code, ExitError,
				out, errOut)
		}

		if _, err := os.Stat(earlier); err != nil {
			t.Fatalf("%s went with bin's lock a folder: %v", earlier, err)
		}

		if strings.Contains(out, earlier) {
			t.Errorf("conflux register listed %s, which is still there, as removed:\n%s", earlier, out)
		}
	})

	t.Run("the run directory", func(t *testing.T) {
		if os.Geteuid() == 0 || runtime.GOOS == "windows" {
			t.Skip("a folder whose mode lets its owner remove nothing in it holds nothing back from root, or on Windows")
		}

		d := configured(t)

		stuck := filepath.Join(d.Run, "anchord")
		for p, body := range map[string]string{filepath.Join(stuck, "kept"): "", d.TokenFile(): "token"} {
			if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
				t.Fatal(err)
			}

			if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
		}

		if err := os.Chmod(stuck, 0o500); err != nil {
			t.Fatal(err)
		}

		t.Cleanup(func() { _ = os.Chmod(stuck, 0o700) })

		standInService(t, &fakeManager{d: d})

		out, errOut, code := capture(t, "register")
		if code != ExitOK || !strings.Contains(errOut, stuck) {
			t.Errorf("conflux register exited %d, want %d warning of %s, which it could not remove:\n%s%s", code,
				ExitOK, stuck, out, errOut)
		}

		for _, p := range []string{stuck, d.TokenFile()} {
			if _, err := os.Lstat(p); err == nil && strings.Contains(out, "  "+p+"\n") {
				t.Errorf("conflux register listed %s, which is still there, as removed:\n%s", p, out)
			}
		}
	})

	t.Run("a killed run's root a run took", func(t *testing.T) {
		d := configured(t)

		root := paths.EphemeralCandidates()[0]
		if err := os.Mkdir(root, 0o700); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(root, "serve.lock"), nil, 0o600); err != nil {
			t.Fatal(err)
		}

		// The run that takes the root as the killed run's lock is let go of, and what it puts there.
		taken := filepath.Join(root, "taken")

		was := removeEphemeral
		defer func() { removeEphemeral = was }()

		removeEphemeral = func(e paths.Dirs, unlock func(), r daemon.Reporter) error {
			return was(e, func() {
				unlock()

				if err := os.WriteFile(taken, []byte("a run's"), 0o600); err != nil {
					t.Error(err)
				}
			}, r)
		}

		standInService(t, &fakeManager{d: d})

		out, errOut, code := capture(t, "register")
		if code != ExitOK {
			t.Fatalf("conflux register exited %d:\n%s%s", code, out, errOut)
		}

		if _, err := os.Lstat(taken); err != nil || strings.Contains(out, "  "+root+"\n") {
			t.Errorf("conflux register removed what a run put in the root it took, or listed %s as removed "+
				"(Lstat: %v):\n%s", root, err, out)
		}
	})
}

// TestTidyRemovesAnEphemeralRootNotAsConfluxMakesOne: the conflux an update put in place removes a
// killed run's root, as conflux's by its name, whatever is there: one not as conflux makes a root -- one
// every account may write, holding a lock and a name of somebody's, or, on Unix, a link -- removed as
// itself, nothing in it read and no lock in it taken, where a link leads never touched; one as conflux
// makes a root, whatever it holds, emptied under its lock. Each is listed.
func TestTidyRemovesAnEphemeralRootNotAsConfluxMakesOne(t *testing.T) {
	anchortest.Require(t) // it extracts the pair afresh

	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	elsewhere := t.TempDir()

	kept := filepath.Join(elsewhere, "serve.lock")
	if err := os.WriteFile(kept, []byte("not conflux's"), 0o600); err != nil {
		t.Fatal(err)
	}

	for name, c := range map[string]struct {
		plant func(t *testing.T, root string)
		ours  bool
	}{
		"holding a name conflux never makes there": {func(t *testing.T, root string) {
			plantIn(t, root, "notes.txt", "serve.lock")
		}, true},
		"every account may write": {func(t *testing.T, root string) {
			if runtime.GOOS == "windows" {
				t.Skip("a mode says nothing of a Windows root")
			}

			plantIn(t, root, "notes.txt", "serve.lock")

			if err := os.Chmod(root, 0o777); err != nil {
				t.Fatal(err)
			}
		}, false},
		"a link": {func(t *testing.T, root string) {
			if runtime.GOOS == "windows" {
				t.Skip("a junction at an ephemeral root's name is " +
					"TestUninstallRemovesAJunctionAtAnEphemeralRootsName's there")
			}

			if err := os.Symlink(elsewhere, root); err != nil {
				t.Fatal(err)
			}
		}, false},
	} {
		t.Run(name, func(t *testing.T) {
			d := configured(t)

			root := paths.EphemeralCandidates()[0]
			c.plant(t, root)

			var reaped []string

			was := removeEphemeral
			defer func() { removeEphemeral = was }()

			removeEphemeral = func(e paths.Dirs, unlock func(), r daemon.Reporter) error {
				reaped = append(reaped, e.State)

				return was(e, unlock, r)
			}

			standInService(t, &fakeManager{d: d})

			out, errOut, code := capture(t, "register")
			if code != ExitOK || !strings.Contains(out, "  "+root+"\n") {
				t.Errorf("conflux register beside a killed run's root %s exited %d, want %d listing it:\n%s%s", name, code,
					ExitOK, out, errOut)
			}

			if _, err := os.Lstat(root); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("conflux register left %s (Lstat: %v)", root, err)
			}

			if c.ours != (len(reaped) == 1) {
				t.Errorf("conflux register took the lock of %q, want it taken only in a root as conflux makes one", reaped)
			}

			if b, err := os.ReadFile(kept); err != nil || string(b) != "not conflux's" {
				t.Errorf("where a link at the root's name led lost what is in it: %q, %v", b, err)
			}
		})
	}
}

// plantIn makes the directory dir, at 0700, holding each of names, somebody's.
func plantIn(t *testing.T, dir string, names ...string) {
	t.Helper()

	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	for _, name := range names {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("somebody's"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// TestTidyLeavesWhatAHeldLockGuards: what an atomic write left in the state directory is removed only
// where nothing holds the state's lock, which every writer of the manifest and the state holds; while
// something does -- a conflux enrol, say -- what it may be writing is left, with the lock.
func TestTidyLeavesWhatAHeldLockGuards(t *testing.T) {
	anchortest.Require(t) // it extracts the pair afresh

	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	d := configured(t)

	staged := filepath.Join(d.State, ".tmp-123")
	if err := os.WriteFile(staged, []byte("a write under way"), 0o600); err != nil {
		t.Fatal(err)
	}

	unlock, err := flock.Acquire(d.LockFile())
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()

	standInService(t, &fakeManager{d: d})

	out, errOut, code := capture(t, "register")
	if code != ExitOK {
		t.Fatalf("conflux register exited %d:\n%s%s", code, out, errOut)
	}

	for _, p := range []string{staged, d.LockFile()} {
		if _, err := os.Lstat(p); err != nil || strings.Contains(out, "  "+p+"\n") {
			t.Errorf("conflux register, the state's lock held, removed or listed %s (Lstat: %v):\n%s", p, err, out)
		}
	}
}
