package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/libexec"
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

// TestObservingAloneStartsNoAnchor: a machine that only observes has its daemon started
// able to, and the observer started in it, and nothing else -- no anchor, no enrolment, no
// credential -- and is ready once the observer is.
func TestObservingAloneStartsNoAnchor(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a console control event needs the console this test shares")
	}

	t.Setenv(fakeAnchorctlStatusEnv, "none")
	t.Setenv(fakeAnchorctlObserverEnv, "running")

	t.Setenv(fakeAnchordListenEnv, "1")

	s, log := supervised(t, "serve")

	if err := config.Save(s.Dirs, &config.Config{Mode: config.ModeObserve, Observer: &config.Observer{}}); err != nil {
		t.Fatal(err)
	}

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
		t.Errorf("anchorctl ran %v: the observer was never started", cmds)
	}

	if slices.Contains(cmds, "start") || slices.Contains(cmds, "renew") {
		t.Errorf("anchorctl ran %v: observing alone started an anchor", cmds)
	}

	if config.HasManifest(s.Dirs) {
		t.Error("observing alone enrolled")
	}
}

// TestTheObserverOutlivesAnAnchorThatCannotComeUp: beside an anchor, the observer starts
// first, and an anchor that cannot come up for now -- an enrolment nobody answers -- leaves
// the daemon, the observer and its inventory running, for the watcher to bring the anchor up
// later, rather than ending the cycle and the inventory with it.
func TestTheObserverOutlivesAnAnchorThatCannotComeUp(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a console control event needs the console this test shares")
	}

	t.Setenv(fakeAnchorctlStatusEnv, "none")
	t.Setenv(fakeAnchorctlObserverEnv, "running")

	t.Setenv(fakeAnchordListenEnv, "1")

	s, log := supervised(t, "serve")

	cfg := &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}, Observer: &config.Observer{},
		Proxies: []string{"8080=127.0.0.1:1"}, APIBaseURL: "http://127.0.0.1:1"}
	if err := config.Save(s.Dirs, cfg); err != nil {
		t.Fatal(err)
	}

	stop := cycling(t, s)

	eventually(t, "the observer starting", func() bool { return slices.Contains(ran(t, log), "observe") })

	// Long enough for the enrolment to have been refused: nothing listens on port 1.
	time.Sleep(time.Second)

	if IsReady(s.Dirs) {
		t.Error("ready with no anchor up")
	}

	if err := stop(); err != nil {
		t.Errorf("the cycle ended with %v, where the anchor's failure should have left it running", err)
	}

	if cmds := ran(t, log); slices.Index(cmds, "observe") < 0 || slices.Contains(cmds, "start") {
		t.Errorf("anchorctl ran %v; want the observer started and no anchor", cmds)
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

	if err := config.Save(s.Dirs, &config.Config{Mode: config.ModeObserve, Observer: &config.Observer{}}); err != nil {
		t.Fatal(err)
	}

	var err error

	returns(t, "a cycle the host refuses", func() { err = s.cycle(t.Context()) })

	if !Permanent(err) {
		t.Errorf("the cycle ended with %v, which is not refused for good", err)
	}
}
