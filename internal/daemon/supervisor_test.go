package daemon

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/anchorctl"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/libexec"
	"github.com/veil-net/conflux/internal/paths"
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

	if _, err := loadConfig(d); !errors.Is(err, ErrNotConfigured) {
		t.Errorf("no conflux.json: %v, want ErrNotConfigured", err)
	}

	if err := os.WriteFile(d.ConfigFile(), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	if _, err := loadConfig(d); !Permanent(err) {
		t.Errorf("a conflux.json that does not parse: %v, want it refused for good", err)
	}

	if err := os.Remove(d.ConfigFile()); err != nil {
		t.Fatal(err)
	}

	// A read that fails, which a directory in its place makes on every platform.
	if err := os.Mkdir(d.ConfigFile(), 0o700); err != nil {
		t.Fatal(err)
	}

	if _, err := loadConfig(d); err == nil || Permanent(err) {
		t.Errorf("a conflux.json that could not be read: %v, want it tried again", err)
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

// credentialed gives d a current credential in the taint supervised configures, which nothing
// asks to renew yet.
func credentialed(t *testing.T, d paths.Dirs) {
	t.Helper()

	if err := config.SaveManifest(d, handed(t, newIssuer(t), time.Now(), time.Now().Add(30*24*time.Hour))); err != nil {
		t.Fatal(err)
	}
}

// TestObservingAloneEnrolsFirstAndStartsNoAnchor: a machine that only observes runs the
// observer under its own credential, so it enrols first, as up does, and hands the observer the
// manifest it saved, on stdin; it records the identity the observer reports running as, which
// its renewals name; it starts no anchor; and it is ready once the observer is.
func TestObservingAloneEnrolsFirstAndStartsNoAnchor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a console control event needs the console this test shares")
	}

	t.Setenv(fakeAnchorctlStatusEnv, "none")
	t.Setenv(fakeAnchorctlObserverEnv, "running")
	t.Setenv(fakeAnchordListenEnv, "1")

	observed := filepath.Join(t.TempDir(), "observed")
	t.Setenv(fakeAnchorctlObservedEnv, observed)

	s, log := supervised(t, "serve")
	api, asked, _ := enroller(t, []string{"t"})

	cfg := &config.Config{Mode: config.ModeObserve, Observer: &config.Observer{}, Taints: []string{"t"}, APIBaseURL: api.URL}
	if err := config.Save(s.Dirs, cfg); err != nil {
		t.Fatal(err)
	}

	stop := cycling(t, s)

	eventually(t, "the readiness marker", func() bool { return IsReady(s.Dirs) })

	if err := stop(); err != nil {
		t.Errorf("the cycle ended with %v", err)
	}

	cmds := ran(t, log)
	if slices.Contains(cmds, "start") || slices.Contains(cmds, "renew") {
		t.Errorf("anchorctl ran %v: observing alone started an anchor", cmds)
	}

	saved, err := config.LoadManifest(s.Dirs)
	if err != nil {
		t.Fatalf("observing alone enrolled nothing: %v", err)
	}

	if !slices.Equal(*asked, cfg.Taints) {
		t.Errorf("enrolled in %v, want %v", *asked, cfg.Taints)
	}

	if got, _ := os.ReadFile(observed); strings.TrimSpace(string(got)) != strings.TrimSpace(string(saved)) {
		t.Errorf("the observer was handed %q on stdin, want the manifest saved", got)
	}

	if st, _ := config.LoadState(s.Dirs); st.AnchorID != fakeAnchorID {
		t.Errorf("the state records AnchorID %q, want the observer's %q", st.AnchorID, fakeAnchorID)
	}
}

// TestTheObserverOutlivesAnAnchorThatCannotComeUp: beside an anchor, the observer starts once
// the credential is held and before the anchor, and an anchor that cannot come up for now -- a
// start anchorctl refuses -- leaves the daemon, the observer and its inventory running, for the
// watcher to bring the anchor up later, rather than ending the cycle and the inventory with it.
// The service manager is told the unit started, or systemd would fail it after TimeoutStartSec
// and take the observer down anyway; the marker, which says an anchor is up, is not written.
func TestTheObserverOutlivesAnAnchorThatCannotComeUp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a console control event needs the console this test shares")
	}

	t.Setenv(fakeAnchorctlStatusEnv, "none")
	t.Setenv(fakeAnchorctlObserverEnv, "running")
	t.Setenv(fakeAnchorctlFailEnv, "start")
	t.Setenv(fakeAnchordListenEnv, "1")

	observed := filepath.Join(t.TempDir(), "observed")
	t.Setenv(fakeAnchorctlObservedEnv, observed)

	s, log := supervised(t, "serve")
	s.Ready = make(chan struct{})

	cfg := &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}, Observer: &config.Observer{},
		Proxies: []string{"8080=127.0.0.1:1"}}
	if err := config.Save(s.Dirs, cfg); err != nil {
		t.Fatal(err)
	}

	credentialed(t, s.Dirs)

	stop := cycling(t, s)

	// Closed once the anchor's start has been refused and the cycle has decided to go on
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
		t.Errorf("the cycle ended with %v, where the anchor's failure should have left it running", err)
	}

	if cmds := ran(t, log); slices.Index(cmds, "observe") < 0 || slices.Index(cmds, "observe") > slices.Index(cmds, "start") {
		t.Errorf("anchorctl ran %v; want the observer started, then the anchor's start", cmds)
	}

	if _, err := os.Stat(observed); err != nil {
		t.Errorf("the observer was handed no credential, so it never ran: %v", err)
	}
}

// TestACredentialThatCannotBeHadEndsTheCycle: the observer runs under the machine's credential
// as the anchor does, so an enrolment the API does not answer leaves nothing to run: the cycle
// ends, as up's does, for the restart loop to try again, with no observer started and nothing
// told the unit started.
func TestACredentialThatCannotBeHadEndsTheCycle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a console control event needs the console this test shares")
	}

	t.Setenv(fakeAnchorctlStatusEnv, "none")
	t.Setenv(fakeAnchorctlObserverEnv, "running")
	t.Setenv(fakeAnchordListenEnv, "1")
	t.Setenv("CONFLUX_ALLOW_INSECURE_API", "1")

	s, log := supervised(t, "serve")
	s.Ready = make(chan struct{})

	for name, cfg := range map[string]*config.Config{
		"observing alone":  {Mode: config.ModeObserve, Observer: &config.Observer{}},
		"beside an anchor": {Mode: config.ModeProxy, Observer: &config.Observer{}, Proxies: []string{"8080=127.0.0.1:1"}},
	} {
		cfg.Taints, cfg.APIBaseURL = []string{"t"}, "http://127.0.0.1:1"
		if err := config.Save(s.Dirs, cfg); err != nil {
			t.Fatal(err)
		}

		var err error

		returns(t, name+": a cycle with no credential to be had", func() { err = s.cycle(t.Context()) })

		if err == nil {
			t.Errorf("%s: the cycle ended with no error", name)
		}
	}

	select {
	case <-s.Ready:
		t.Error("the unit was said to have started")
	default:
	}

	if cmds := ran(t, log); slices.Contains(cmds, "observe") {
		t.Errorf("anchorctl ran %v; the observer was started with no credential", cmds)
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

	if err := config.Save(s.Dirs, &config.Config{Mode: config.ModeObserve, Observer: &config.Observer{}, Taints: []string{"t"}}); err != nil {
		t.Fatal(err)
	}

	credentialed(t, s.Dirs)

	var err error

	returns(t, "a cycle the host refuses", func() { err = s.cycle(t.Context()) })

	if !Permanent(err) {
		t.Errorf("the cycle ended with %v, which is not refused for good", err)
	}
}

// TestObservingAloneRenews: the renewal timer runs for a machine that only observes, as it does
// beside an anchor, and renews by the AnchorID the observer reported running as, installing the
// chain in the observer.
func TestObservingAloneRenews(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a console control event needs the console this test shares")
	}

	t.Setenv(fakeAnchorctlStatusEnv, "none")
	t.Setenv(fakeAnchorctlObserverEnv, "running")
	t.Setenv(fakeAnchordListenEnv, "1")

	s, _ := supervised(t, "serve")
	is := newIssuer(t)

	if err := config.Save(s.Dirs, &config.Config{Mode: config.ModeObserve, Observer: &config.Observer{},
		Taints: []string{"t"}, APIBaseURL: is.srv.URL}); err != nil {
		t.Fatal(err)
	}

	// Due, and with no AnchorID recorded yet, so nothing renews it before the observer starts
	// and reports one: the timer is what does.
	if err := config.SaveManifest(s.Dirs, handed(t, is, time.Now().Add(-25*24*time.Hour), time.Now().Add(5*24*time.Hour))); err != nil {
		t.Fatal(err)
	}

	_, observer := renewedInto(t)

	stop := cycling(t, s)

	eventually(t, "the renewed chain reaching the observer", func() bool { return handedTo(observer, is.chain) })

	if err := stop(); err != nil {
		t.Errorf("the cycle ended with %v", err)
	}

	if got := is.asked(t).AnchorID; got != fakeAnchorID {
		t.Errorf("renewed for %q, want the observer's %q", got, fakeAnchorID)
	}
}

// recorder is a Reporter that keeps what it was told.
type recorder struct {
	mu           sync.Mutex
	steps, warns []string
}

func (r *recorder) Step(format string, a ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.steps = append(r.steps, fmt.Sprintf(format, a...))
}

func (r *recorder) Warn(format string, a ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.warns = append(r.warns, fmt.Sprintf(format, a...))
}

// said is every step and warning so far.
func (r *recorder) said() (steps, warns []string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return slices.Clone(r.steps), slices.Clone(r.warns)
}

// TestThreeRefusalsEndTheService: a configuration refused for good on three starts in a row
// ends the restart loop with an error Permanent reports -- serve's exit 70, which no service
// manager restarts -- after a second's wait and then two between the starts.
func TestThreeRefusalsEndTheService(t *testing.T) {
	s, _ := supervised(t, "serve")

	r := &recorder{}
	s.Reporter = r

	// A configuration conflux refuses, which every spawn reads afresh.
	if err := os.WriteFile(s.Dirs.ConfigFile(), []byte(`{"version":1,"mode":"neither"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	ended := make(chan error, 1)
	go func() { ended <- s.loop(t.Context()) }()

	select {
	case err := <-ended:
		if !Permanent(err) {
			t.Errorf("the loop ended with %v, which serve would not exit 70 on", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the restart loop went on starting a configuration refused for good")
	}

	steps, _ := r.said()
	if want := []string{"restarting in 1s", "restarting in 2s"}; !slices.Equal(steps, want) {
		t.Errorf("the loop said %q, want %q", steps, want)
	}
}

// TestTheKeeperBacksOff: a failed try holds the next off for the backoff, which doubles
// between the keeper's bounds -- the restart loop's from a second to thirty, the watcher's from
// its look to rebuildBackoffMax -- and a try that works starts it over; only tries refused for
// good, rebuildRefusals of them in a row, give up, and a failure a retry may fix starts that
// count over -- a healthy run does, for the supervisor's restart loop.
func TestTheKeeperBacksOff(t *testing.T) {
	transient, refused := errors.New("connection refused"), &permanentError{err: errors.New("refused")}

	for name, tc := range map[string]struct {
		k     *keeper
		holds []time.Duration
	}{
		"the restart loop's": {newKeeper(restartBackoffMin, restartBackoffMax), []time.Duration{
			time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 30 * time.Second, 30 * time.Second,
		}},
		"the watcher's on a link": {newKeeper(linkCheckInterval, rebuildBackoffMax), []time.Duration{
			10 * time.Second, 20 * time.Second, 30 * time.Second, 30 * time.Second,
		}},
	} {
		k := tc.k

		for _, want := range tc.holds {
			before := time.Now()

			if k.failed(transient) {
				t.Fatalf("%s: gave up on a failure a retry may fix", name)
			}

			if k.due() {
				t.Errorf("%s: due again at once after a failure that holds the next try off for %s", name, want)
			}

			if held := k.notBefore.Sub(before); held < want || held > want+time.Second {
				t.Errorf("%s: held the next try off for %s, want %s", name, held, want)
			}
		}

		if k.ok(); !k.due() || k.backoff != k.least {
			t.Errorf("%s: a try that worked left the backoff at %s, due %v", name, k.backoff, k.due())
		}
	}

	k := newKeeper(restartBackoffMin, restartBackoffMax)

	for i, want := range []bool{false, false, false, false, false, true} {
		err := error(refused)
		if i == 2 {
			err = transient
		}

		if got := k.failed(err); got != want {
			t.Errorf("try %d (%v): gave up %v, want %v", i+1, err, got, want)
		}
	}
}

// TestWhatAProbeCannotRecoverFrom: a socket conflux may not reach and a token anchord refuses
// end the wait for readiness at once, since retrying cannot change either; a daemon that does
// not answer yet is waited for.
func TestWhatAProbeCannotRecoverFrom(t *testing.T) {
	for name, err := range map[string]error{
		"a socket conflux may not reach": fmt.Errorf("dial unix /run/conflux/anchord/sock: %w", os.ErrPermission),
		"a token anchord refuses":        &anchorctl.Error{Args: []string{"status"}, Stderr: "anchorctl: unauthenticated: bad token"},
	} {
		if probeIsFatal(err) == nil {
			t.Errorf("%s is waited out as if a retry could fix it", name)
		}
	}

	for name, err := range map[string]error{
		"nothing listening yet": fmt.Errorf("dial unix /run/conflux/anchord/sock: %w", os.ErrNotExist),
		"a status that failed":  &anchorctl.Error{Args: []string{"status"}, Stderr: "anchorctl: connection refused"},
	} {
		if err := probeIsFatal(err); err != nil {
			t.Errorf("%s ended the wait for readiness: %v", name, err)
		}
	}
}
