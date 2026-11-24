package daemon

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/veil-net/conflux/internal/enrol"
	"github.com/veil-net/conflux/internal/paths"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/flock"
	"github.com/veil-net/conflux/internal/libexec"
	"github.com/veil-net/conflux/internal/wintun"
)

// supervised is a supervisor over the stand-in anchord in the given mode, with the
// stand-in anchorctl behind it logging every command it runs to the returned file.
func supervised(t *testing.T, mode string) (*Supervisor, string) {
	t.Helper()
	t.Setenv(fakeAnchordEnv, mode)

	log := filepath.Join(t.TempDir(), "anchorctl.log")
	t.Setenv(fakeAnchorctlLogEnv, log)

	d := dirs(t)

	if err := config.Save(d, &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	s := &Supervisor{Dirs: d, tools: &libexec.Tools{Anchord: os.Args[0]}, tail: newRing(tailLines), ctl: fakeCtl(t)}

	return s, log
}

// returns fails the test if f has not returned within a few seconds.
func returns(t *testing.T, what string, f func()) {
	t.Helper()

	done := make(chan struct{})

	go func() {
		f()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not return", what)
	}
}

// TestShutdownAfterTheDaemonHasGone: a daemon that died has been waited for already, by
// whichever wait noticed, and shutdown must not wait for that exit a second time. It
// did, forever, so a supervisor whose anchord crashed never restarted it.
func TestShutdownAfterTheDaemonHasGone(t *testing.T) {
	s, log := supervised(t, "1")

	_, c, err := s.spawn(t.Context())
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}

	if err := s.waitReady(t.Context(), c); err == nil {
		t.Fatal("waitReady reported a daemon that died as ready")
	}

	returns(t, "shutdown after the daemon exited", func() { s.shutdown(c) })

	// Both streams, in the order anchord wrote them, the unfinished last line included.
	if got, want := s.tail.String(), "  anchord: anchord starting\n  anchord: "+fakeAnchordLastWords; got != want {
		t.Errorf("the tail reads\n%s\nwant\n%s", got, want)
	}

	// Nothing is asked of a daemon that is not there.
	if b, _ := os.ReadFile(log); len(b) > 0 {
		t.Errorf("shutdown ran anchorctl %q against a daemon that had exited", b)
	}
}

// TestShutdownSignalsARunningDaemon: anchord closes its anchor on SIGTERM, so where a
// signal can be delivered it is the whole of shutdown -- the daemon exits of its own
// accord, not killed, and no anchorctl is forked to ask for the same close first.
func TestShutdownSignalsARunningDaemon(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a console control event needs the console this test shares")
	}

	s, log := supervised(t, "serve")

	_, c, err := s.spawn(t.Context())
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}

	// Once it is listening, as a daemon the supervisor has probed is: a signal that
	// arrives before the handler is installed is the default one, and kills.
	for deadline := time.Now().Add(5 * time.Second); !strings.Contains(s.tail.String(), "anchord listening"); {
		if time.Now().After(deadline) {
			t.Fatalf("the stand-in anchord never said it was listening:\n%s", s.tail)
		}

		time.Sleep(5 * time.Millisecond)
	}

	returns(t, "shutdown of a running daemon", func() { s.shutdown(c) })

	select {
	case <-c.exited:
	default:
		t.Fatal("shutdown returned with anchord still running")
	}

	if c.err != nil {
		t.Errorf("anchord did not exit on its signal: %v", c.err)
	}

	if b, _ := os.ReadFile(log); len(b) > 0 {
		t.Errorf("shutdown ran anchorctl %q to close an anchor SIGTERM closes", b)
	}
}

// TestTheTailKeepsTheLastLinesInOrder: the tail is the daemon's last words, oldest
// first, before and after it wraps.
func TestTheTailKeepsTheLastLinesInOrder(t *testing.T) {
	r := newRing(3)

	if got := r.String(); got != "  (anchord said nothing)" {
		t.Errorf("an empty tail reads %q", got)
	}

	want := map[int]string{
		1: "  anchord: 1",
		3: "  anchord: 1\n  anchord: 2\n  anchord: 3",
		5: "  anchord: 3\n  anchord: 4\n  anchord: 5",
		7: "  anchord: 5\n  anchord: 6\n  anchord: 7",
	}

	for i := 1; i <= 7; i++ {
		r.add(strconv.Itoa(i))

		if w, ok := want[i]; ok {
			if got := r.String(); got != w {
				t.Errorf("after %d lines the tail is\n%s\nwant\n%s", i, got, w)
			}
		}
	}
}

// TestTheTailIsEachDaemonsOwn: what a failure is reported in is the last anchord's own words,
// not those of one that died before it under the same supervisor.
func TestTheTailIsEachDaemonsOwn(t *testing.T) {
	s, _ := supervised(t, "1")

	for range 2 {
		_, c, err := s.spawn(t.Context())
		if err != nil {
			t.Fatalf("spawn: %v", err)
		}

		<-c.exited
		s.shutdown(c)
	}

	if got, want := s.tail.String(), "  anchord: anchord starting\n  anchord: "+fakeAnchordLastWords; got != want {
		t.Errorf("the second anchord's tail reads\n%s\nwant\n%s", got, want)
	}
}

// TestAConfigAnchordWouldRefuseIsNotStarted: anchord reads its -config at startup and
// will not come up on a block it refuses. Started anyway, that is a daemon dying before
// it answers, which the restart loop retries for ever; refused here, it is permanent,
// and the supervisor stops in three.
func TestAConfigAnchordWouldRefuseIsNotStarted(t *testing.T) {
	s, _ := supervised(t, "serve")

	if err := config.Save(s.Dirs, &config.Config{
		Mode: config.ModeProxy, Taints: []string{"t"},
		Export: &config.Export{Enabled: true, Endpoint: "collector", Metrics: true},
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	_, c, err := s.spawn(t.Context())
	if c != nil {
		s.shutdown(c)
		t.Fatal("anchord was started on a configuration it refuses")
	}

	if !Permanent(err) {
		t.Errorf("the refusal is not permanent, so it would be retried for ever: %v", err)
	}

	if _, statErr := os.Stat(s.Dirs.DaemonConfigFile()); statErr == nil {
		t.Error("the refused block was rendered for anchord anyway")
	}
}

// TestAConfigurationIsReadOneWayEverywhere: the supervisor's start, every spawn and every
// bring-up decide alike what a conflux.json they cannot use means -- none is nothing to
// start, one that will not parse is refused for good, and one that could not be read is
// tried again -- so a file broken under a running service is not retried for ever by one
// reader and refused by another.
func TestAConfigurationIsReadOneWayEverywhere(t *testing.T) {
	d := dirs(t)

	if _, _, err := loadConfig(d); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("no conflux.json: %v, want ErrNotConfigured", err)
	}

	if err := os.WriteFile(d.ConfigFile(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, _, err := loadConfig(d); !Permanent(err) {
		t.Errorf("a conflux.json that does not parse: %v, want it refused for good", err)
	}

	if err := os.Remove(d.ConfigFile()); err != nil {
		t.Fatal(err)
	}

	// A read that fails, which a directory in its place makes on every platform.
	if err := os.Mkdir(d.ConfigFile(), 0o700); err != nil {
		t.Fatal(err)
	}

	if _, _, err := loadConfig(d); err == nil || Permanent(err) {
		t.Errorf("a conflux.json that could not be read: %v, want it tried again", err)
	}
}

// TestARefusedConfigurationIsLeftAsWritten: a conflux.json the start refuses -- one that does
// not parse, one a newer conflux wrote, one Validate refuses -- is refused for good and left
// exactly as it was written, so whoever edited it sees what they wrote; the start writes back
// in conflux's form only what it reads and takes.
func TestARefusedConfigurationIsLeftAsWritten(t *testing.T) {
	for name, raw := range map[string]string{
		"does not parse":    `{not json`,
		"a newer conflux's": `{"version":99,"mode":"proxy","taints":["t"]}`,
		"Validate refuses":  `{"version":1,"mode":"neither","taints":["t"],"proxys":["8080=127.0.0.1:1"]}` + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			d := dirs(t)

			if err := os.WriteFile(d.ConfigFile(), []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}

			if err := (&Supervisor{Dirs: d}).Run(t.Context()); !Permanent(err) {
				t.Errorf("Run = %v, want a refusal for good", err)
			}

			if got, _ := os.ReadFile(d.ConfigFile()); string(got) != raw {
				t.Errorf("the refused conflux.json was rewritten:\n%s", got)
			}
		})
	}
}

// cycling runs one cycle of s in the background, and returns how to end it and wait.
func cycling(t *testing.T, s *Supervisor) (stop func() error) {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)

	go func() { done <- s.cycle(ctx) }()

	return func() error {
		cancel()

		select {
		case err := <-done:
			return err
		case <-time.After(15 * time.Second):
			t.Fatal("the cycle did not end")

			return nil
		}
	}
}

// eventually waits for cond, or fails the test saying what was waited for.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()

	for deadline := time.Now().Add(10 * time.Second); !cond(); {
		if time.Now().After(deadline) {
			t.Fatalf("%s never happened", what)
		}

		time.Sleep(10 * time.Millisecond)
	}
}

// ran is the commands the stand-in anchorctl ran, in order.
func ran(t *testing.T, log string) []string {
	t.Helper()

	b, _ := os.ReadFile(log)

	return strings.Fields(string(b))
}

// credentialed gives the machine at d a current alpha credential in the taint "t", which
// renews nowhere a test reaches and is not due: a start reads it and asks nobody anything.
func credentialed(t *testing.T, d paths.Dirs) config.Envelope {
	t.Helper()

	saveDoc(t, d, map[string]any{
		"formatVersion": 1, "kind": "anchor", "identity": "aa", "genesis": "bb",
		"chain":      base64.StdEncoding.EncodeToString([]byte("the chain")),
		"issuedAt":   time.Now().Add(-time.Hour).UTC().Format(enrol.ManifestTime),
		"notAfter":   time.Now().Add(29 * 24 * time.Hour).UTC().Format(enrol.ManifestTime),
		"taints":     []string{"t"},
		"bootstrap":  []string{"genesis.veilnet.com.au:4700"},
		"renewalUrl": "https://api.invalid/ghosts/alpha/renew", "renewalAuth": "anchor-id",
	})

	env, err := config.LoadManifest(d)
	if err != nil {
		t.Fatal(err)
	}

	return env
}

// TestObservingAloneRunsUnderTheMachinesCredential: a machine that only observes starts the
// observer in its daemon under the machine's own credential -- the manifest, on anchorctl's
// stdin, never named in argv -- and nothing else: no anchor. It records the AnchorID the
// observer runs as, which is what the credential is renewed by, and is ready once the
// observer is.
func TestObservingAloneRunsUnderTheMachinesCredential(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a console control event needs the console this test shares")
	}

	t.Setenv(fakeAnchorctlStatusEnv, "none")
	t.Setenv(fakeAnchorctlObserverEnv, "running")
	t.Setenv(fakeAnchordListenEnv, "1")

	observed := filepath.Join(t.TempDir(), "observed")
	t.Setenv(fakeAnchorctlObservedEnv, observed)

	s, log := supervised(t, "serve")

	if err := config.Save(s.Dirs, &config.Config{Mode: config.ModeObserve, Taints: []string{"t"}, Observer: &config.Observer{}}); err != nil {
		t.Fatal(err)
	}

	env := credentialed(t, s.Dirs)

	stop := cycling(t, s)

	eventually(t, "the readiness marker", func() bool { return IsReady(s.Dirs) })

	if b, _ := os.ReadFile(s.Dirs.ReadyFile()); !strings.Contains(string(b), "observer") {
		t.Errorf("the marker is %q, which does not say the observer is up", b)
	}

	if err := stop(); err != nil {
		t.Errorf("the cycle ended with %v", err)
	}

	cmds := ran(t, log)
	if !slices.Contains(cmds, "observe") {
		t.Fatalf("anchorctl ran %v: the observer was never started", cmds)
	}

	if slices.Contains(cmds, "start") {
		t.Errorf("anchorctl ran %v: observing alone started an anchor", cmds)
	}

	if got, _ := os.ReadFile(observed); string(got) != string(env) {
		t.Errorf("the observer was started with %q on stdin, want the machine's manifest", got)
	}

	if st, err := config.LoadState(s.Dirs); err != nil || st.AnchorID != fakeAnchorID {
		t.Errorf("the state records AnchorID %q (%v), want the one the observer runs as, %s", st.AnchorID, err, fakeAnchorID)
	}
}

// TestObservingAloneEnrolsFirst: a machine that only observes and holds no credential yet is
// enrolled in its configured taints before the observer starts, as an anchor's is, and the
// enrolment is kept.
func TestObservingAloneEnrolsFirst(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a console control event needs the console this test shares")
	}

	t.Setenv(fakeAnchorctlStatusEnv, "none")
	t.Setenv(fakeAnchorctlObserverEnv, "running")
	t.Setenv(fakeAnchordListenEnv, "1")

	srv, asked, _ := enroller(t, []string{"t"})

	s, log := supervised(t, "serve")

	if err := config.Save(s.Dirs, &config.Config{
		Mode: config.ModeObserve, Taints: []string{"t"}, Observer: &config.Observer{}, APIBaseURL: srv.URL,
	}); err != nil {
		t.Fatal(err)
	}

	stop := cycling(t, s)

	eventually(t, "the readiness marker", func() bool { return IsReady(s.Dirs) })

	if err := stop(); err != nil {
		t.Errorf("the cycle ended with %v", err)
	}

	if !config.HasManifest(s.Dirs) {
		t.Error("observing alone with no credential started without enrolling")
	}

	if !slices.Equal(*asked, []string{"t"}) {
		t.Errorf("enrolled in %v, want the configured taints", *asked)
	}

	if cmds := ran(t, log); !slices.Contains(cmds, "observe") {
		t.Errorf("anchorctl ran %v: the observer was never started", cmds)
	}
}

// TestTheObserverOutlivesAnAnchorThatDoesNotComeUp: beside an anchor, the observer starts
// first, under the credential, and an anchor whose start then fails -- for now, refused for
// good, or on Windows for a driver that could not be had, which is fetched before the start
// takes conflux.lock (TestTheDriverIsFetchedOutsideTheLock) and so before the observer starts --
// leaves the daemon, the observer and its inventory running, for the watcher to bring the
// anchor up later, rather than ending the cycle and the inventory with it. A refusal for
// good is the watcher's to count, as a rebuild's are, which gives the anchor up after
// rebuildRefusals of them and keeps the observer (TestTheWatcherCountsTheStartsRefusal). The
// service manager is told the unit started, or systemd would fail it after TimeoutStartSec and
// take the observer down anyway; the marker, which says an anchor is up, is not written.
func TestTheObserverOutlivesAnAnchorThatDoesNotComeUp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a console control event needs the console this test shares")
	}

	for name, c := range map[string]struct {
		mode   config.Mode // the anchor's
		refuse string      // how the stand-in anchorctl refuses its start, or nothing
		driver error       // what fetching Windows' driver fails with, or nothing
		steps  []string    // the driver's fetch, the observer's start and anchorctl's start that ran, in order
	}{
		"whose start fails for now": {mode: config.ModeProxy, refuse: fakeAnchorctlFailEnv, steps: []string{"observe", "start"}},
		// An argument vector anchorctl will not take, exit 2.
		"whose start is refused for good": {mode: config.ModeProxy, refuse: fakeAnchorctlRefuseEnv,
			steps: []string{"observe", "start"}},
		// An interface on Windows, with wintun.net out of reach: no anchorctl start without it.
		"whose driver cannot be had": {mode: config.ModeTUN, driver: errors.New("wintun.net did not answer"),
			steps: []string{"wintun", "observe"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(fakeAnchorctlStatusEnv, "none")
			t.Setenv(fakeAnchorctlObserverEnv, "running")
			t.Setenv(fakeAnchordListenEnv, "1")

			if c.refuse != "" {
				t.Setenv(c.refuse, "start")
			}

			s, log := supervised(t, "serve")
			s.Ready = make(chan struct{})

			fetchingDriver(t, log, c.driver)

			cfg := &config.Config{Mode: c.mode, Taints: []string{"t"}, Observer: &config.Observer{}}
			if c.mode == config.ModeProxy {
				cfg.Proxies = []string{"8080=127.0.0.1:1"}
			}

			if err := config.Save(s.Dirs, cfg); err != nil {
				t.Fatal(err)
			}

			credentialed(t, s.Dirs)

			stop := cycling(t, s)

			// Closed once the anchor's start has failed and the cycle has decided to go on
			// without it.
			eventually(t, "the service manager being told the unit started", func() bool {
				select {
				case <-s.Ready:
					return true
				default:
					return false
				}
			})

			if IsReady(s.Dirs) {
				t.Error("ready with no anchor up")
			}

			if err := stop(); err != nil {
				t.Errorf("the cycle ended with %v, where the observer should have kept it running", err)
			}

			cmds := ran(t, log)
			if steps := slices.DeleteFunc(slices.Clone(cmds), func(cmd string) bool {
				return !slices.Contains([]string{"wintun", "observe", "start"}, cmd)
			}); !slices.Equal(steps, c.steps) {
				t.Errorf("anchorctl ran %v; want, of the driver's fetch and the two starts, %v", cmds, c.steps)
			}
		})
	}
}

// fetchingDriver stands in for wintun.Ensure, answering err, and records each fetch as "wintun"
// in log, where the stand-in anchorctl records its commands, so the order of the two is read
// off one log.
func fetchingDriver(t *testing.T, log string, err error) {
	t.Helper()

	ensureDriver = func(context.Context, paths.Dirs) error {
		f, openErr := os.OpenFile(log, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if openErr != nil {
			return openErr
		}

		defer f.Close()

		_, _ = fmt.Fprintln(f, "wintun")

		return err
	}

	t.Cleanup(func() { ensureDriver = wintun.Ensure })
}

// TestTheDriverIsFetchedOutsideTheLock: Windows' driver is fetched before the start takes
// conflux.lock, and before a rebuild does, so a first download that hangs -- up to wintun's
// 90-second timeout -- holds back neither `conflux renew` nor up's save of the configuration,
// which wait for that lock. The anchor starts once the driver is had.
func TestTheDriverIsFetchedOutsideTheLock(t *testing.T) {
	for name, bring := range map[string]func(context.Context, *Supervisor, *config.Config) error{
		"the start": func(ctx context.Context, s *Supervisor, cfg *config.Config) error {
			_, anchorErr, err := s.up(ctx, cfg)

			return errors.Join(anchorErr, err)
		},
		"a rebuild": func(ctx context.Context, s *Supervisor, cfg *config.Config) error {
			return s.rebuild(ctx, cfg, false)
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, log := supervised(t, "1")
			credentialed(t, s.Dirs)
			s.priv.Dir = s.Dirs.RootAnchorDir()

			cfg := &config.Config{Mode: config.ModeTUN, Taints: []string{"t"}}
			if err := config.Save(s.Dirs, cfg); err != nil {
				t.Fatal(err)
			}

			fetching, fetched := make(chan struct{}), make(chan struct{})

			ensureDriver = func(context.Context, paths.Dirs) error {
				close(fetching)
				<-fetched

				return nil
			}

			t.Cleanup(func() { ensureDriver = wintun.Ensure })

			done := make(chan error, 1)

			go func() { done <- bring(t.Context(), s, cfg) }()

			select {
			case <-fetching:
			case err := <-done:
				t.Fatalf("brought up without fetching the driver: %v", err)
			case <-time.After(10 * time.Second):
				t.Fatal("the driver was never fetched")
			}

			unlock, free, err := flock.TryAcquire(s.Dirs.LockFile())

			switch {
			case err != nil:
				t.Errorf("TryAcquire: %v", err)
			case free:
				unlock()
			default:
				t.Errorf("%s held conflux.lock while the driver was fetched", name)
			}

			close(fetched)

			select {
			case err := <-done:
				if err != nil {
					t.Errorf("%s: %v", name, err)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("%s did not finish once the driver was had", name)
			}

			if !slices.Contains(ran(t, log), "start") {
				t.Errorf("anchorctl ran %v: the anchor was never started", ran(t, log))
			}
		})
	}
}

// TestNoCredentialNoObserver: the observer runs under the machine's credential, so beside an
// anchor whose enrolment nobody answers neither starts, and the cycle ends to be tried again.
func TestNoCredentialNoObserver(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a console control event needs the console this test shares")
	}

	t.Setenv(fakeAnchorctlStatusEnv, "none")
	t.Setenv(fakeAnchordListenEnv, "1")
	t.Setenv(config.InsecureAPIEnv, "1")

	s, log := supervised(t, "serve")

	if err := config.Save(s.Dirs, &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}, Observer: &config.Observer{},
		Proxies: []string{"8080=127.0.0.1:1"}, APIBaseURL: "http://127.0.0.1:1"}); err != nil {
		t.Fatal(err)
	}

	var err error

	returns(t, "a cycle with no credential to observe under", func() { err = s.cycle(t.Context()) })

	if err == nil || Permanent(err) {
		t.Errorf("the cycle ended with %v, want a failure the next start may not meet", err)
	}

	if cmds := ran(t, log); slices.Contains(cmds, "observe") {
		t.Errorf("anchorctl ran %v: the observer was started with no credential", cmds)
	}
}

// TestAnObserverTheHostRefusesEndsObservingAlone: observing alone, a host that will not let
// the daemon capture is the cycle's failure, and a permanent one: no restart changes it.
func TestAnObserverTheHostRefusesEndsObservingAlone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a console control event needs the console this test shares")
	}

	t.Setenv(fakeAnchorctlStatusEnv, "none")
	t.Setenv(fakeAnchorctlCaptureEnv, "1")
	t.Setenv(fakeAnchordListenEnv, "1")

	s, _ := supervised(t, "serve")

	if err := config.Save(s.Dirs, &config.Config{Mode: config.ModeObserve, Taints: []string{"t"}, Observer: &config.Observer{}}); err != nil {
		t.Fatal(err)
	}

	credentialed(t, s.Dirs)

	var err error

	returns(t, "a cycle the host refuses", func() { err = s.cycle(t.Context()) })

	if !Permanent(err) {
		t.Errorf("the cycle ended with %v, which is not refused for good", err)
	}
}
