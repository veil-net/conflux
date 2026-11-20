package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/anchorctl"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/enrol"
	"github.com/veil-net/conflux/internal/paths"
)

func TestDevicePath(t *testing.T) {
	for spec, want := range map[string]string{
		"/dev/ttyUSB0":        "/dev/ttyUSB0",
		"/dev/ttyUSB0:115200": "/dev/ttyUSB0",
		"/dev/ttyS1:57600":    "/dev/ttyS1",

		// fd:N adopts a descriptor and opens nothing, so there is no path to watch.
		"fd:3": "",

		// Not a spec at all. A watcher that cannot tell what it is looking at
		// watches nothing rather than guessing at a filename.
		"": "",
	} {
		if got := devicePath(spec); got != want {
			t.Errorf("devicePath(%q) = %q, want %q", spec, got, want)
		}
	}
}

// TestGraceIsLongerThanAnchorsOwnDialling is the arithmetic the link watcher rests
// on. anchor starts an uplink dial at most every five seconds plus up to one of jitter,
// each with a 45s timeout, and the slowest line conflux accepts needs ~25s for a realm
// handshake. A grace shorter than that would restart anchors that were about to come
// up on their own.
func TestGraceIsLongerThanAnchorsOwnDialling(t *testing.T) {
	const (
		anchorRedial      = 6 * time.Second
		anchorDialTimeout = 45 * time.Second
		slowestHandshake  = 25 * time.Second
	)

	if linkGrace <= anchorRedial+anchorDialTimeout+slowestHandshake {
		t.Errorf("linkGrace is %s, which does not outlast a %s wait, a %s dial and a %s handshake",
			linkGrace, anchorRedial, anchorDialTimeout, slowestHandshake)
	}

	if linkCheckInterval >= linkGrace {
		t.Errorf("linkCheckInterval %s is not shorter than linkGrace %s, so the grace could never be observed",
			linkCheckInterval, linkGrace)
	}
}

// TestLinkIsDeadWhenTheDeviceGoes: an unplugged adapter is unambiguous, and is not
// made to wait out the grace period that exists for the ambiguous case.
func TestLinkIsDeadWhenTheDeviceGoes(t *testing.T) {
	s := &Supervisor{}

	var zeroSince time.Time

	missing := filepath.Join(t.TempDir(), "ttyUSB0")

	dead, _, reason, _ := s.linkIsDead(t.Context(), missing, &zeroSince)
	if !dead {
		t.Fatal("a device that is not there should be a dead link")
	}

	if reason == "" {
		t.Error("a dead link should say why")
	}
}

// TestBusyInterfaceIsPermanent: an --interface naming one another interface already
// holds is refused on every start. Retrying it to the unit's 90-second timeout leaves the
// reason in the journal and nothing but "job failed" in front of the operator.
func TestBusyInterfaceIsPermanent(t *testing.T) {
	err := &anchorctl.Error{
		Args:   []string{"start", "-tun=true", "-tun-name", "veil0"},
		Stderr: `anchorctl: starting: anchor: opening veil0: tundev: creating "veil0": device or resource busy`,
	}

	if !Permanent(err) {
		t.Error("a TUN name another interface holds should not be retried to the unit timeout")
	}
}

// TestWhatIsPermanent: the refusals no retry changes stop the supervisor in three
// attempts, and the ones a moment fixes do not.
func TestWhatIsPermanent(t *testing.T) {
	anchorctlSaid := func(stderr string) error { return &anchorctl.Error{Stderr: stderr} }

	for name, err := range map[string]error{
		"a configuration conflux refuses": &permanentError{path: "conflux.json", err: errors.New("no taints")},
		"a manifest conflux cannot read":  &permanentError{path: "manifest.b64", err: errors.New("format version 2")},
		"another tree's credential":       anchorctlSaid("anchorctl: anchor: realm root is not the pinned genesis: have x, want y"),
		"no TUN for this daemon": anchorctlSaid("anchorctl: anchor: this host will not give this process a TUN device: " +
			"tundev: creating \"anchor6btpa3gn6\": operation not permitted\n" +
			"  a TUN needs IPv6 on the daemon's host, and CAP_NET_ADMIN on Linux, root on macOS and the BSDs, " +
			"Administrator and wintun.dll on Windows; give the daemon that, or start it in userspace mode"),
		"a host that will not forward": anchorctlSaid("anchorctl: starting: anchor: this host could not be set up to " +
			"forward for the realm: nft: command not found"),
		"taints the credential does not grant": anchorctlSaid("anchorctl: config: anchor: the realm credential does not " +
			"grant this anchor's taints: Taints names [\"dev\"]: realm: the credential does not grant these taints"),
		"conflux's own taints refusal": &permanentError{path: "manifest.b64", err: &enrol.TaintsError{Alpha: true}},
		// What a live anchorctl said to `observe -start` against an anchord with no CAP_NET_RAW.
		"a host that will not let the daemon capture": anchorctlSaid("anchorctl: capture: not permitted: open a packet " +
			"socket: operation not permitted (it needs CAP_NET_RAW)\n  capturing needs CAP_NET_RAW for the daemon on " +
			"Linux, read access to /dev/bpf* on macOS, Administrators or Performance Log Users on Windows; give the daemon " +
			"that, then \"anchorctl observe -start\" again"),
		"a usage error": func() error {
			// The stand-in answers exit 2, anchorctl's usage error, to a status it was
			// not told how to give.
			t.Setenv(fakeAnchorctlStatusEnv, "")
			_, err := fakeCtl(t).Status(t.Context())

			return err
		}(),
	} {
		if !Permanent(err) {
			t.Errorf("%s was not treated as permanent: %v", name, err)
		}
	}

	for name, err := range map[string]error{
		"a subnet not attached yet":         anchorctlSaid("anchorctl: hostnet: not attached to that network: eth1 has no private network"),
		"the daemon went away":              anchorctlSaid("anchorctl: connection refused\n  is anchord running on that socket, and can it reach the peer?"),
		"a network failure":                 errors.New("renew: dial tcp: i/o timeout"),
		"a serial line another process has": anchorctlSaid("anchorctl: starting: uplink: opening /dev/ttyUSB0: device or resource busy"),
		"a call that failed once": func() error {
			t.Setenv(fakeAnchorctlFailEnv, "status")
			_, err := fakeCtl(t).Status(t.Context())

			return err
		}(),
	} {
		if Permanent(err) {
			t.Errorf("%s was treated as permanent; a retry can fix it", name)
		}
	}
}

// TestALostAnchorIsSeen: a daemon still answering with no anchor in it is rebuilt, and a
// daemon that does not answer is left to the restart loop. On a link the gauge is the
// poll, and status is asked only when the gauge cannot be read.
func TestALostAnchorIsSeen(t *testing.T) {
	for name, tc := range map[string]struct {
		status, failing string
		uplink          bool
		want            string
		carrying        bool
	}{
		"an anchor running":               {status: "running"},
		"no anchor":                       {status: "none", want: "anchord holds no anchor any more"},
		"a daemon that does not answer":   {},
		"a link carrying something":       {uplink: true, status: "none", carrying: true},
		"a link with no anchor behind it": {uplink: true, status: "none", failing: "metrics", want: "anchord holds no anchor any more"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(fakeAnchorctlStatusEnv, tc.status)
			t.Setenv(fakeAnchorctlFailEnv, tc.failing)

			// A device that is there: a file stands in for one on every platform.
			var uplink string
			if tc.uplink {
				uplink = filepath.Join(t.TempDir(), "ttyUSB0")
				if err := os.WriteFile(uplink, nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}

			s := &Supervisor{ctl: fakeCtl(t)}

			var zeroSince time.Time

			if l := s.lost(t.Context(), uplink, devicePath(uplink), &zeroSince); l.why != tc.want || l.link || l.carrying != tc.carrying {
				t.Errorf("lost() = %q, link %v, carrying %v; want %q, false, %v", l.why, l.link, l.carrying, tc.want, tc.carrying)
			}
		})
	}
}

// TestTheWatcherGivesUpOnARefusedConfiguration: an anchor lost under a configuration
// that will not build another is rebuilt rebuildRefusals times and then left, rather than
// retried every thirty seconds for ever; the watch says so, which ends the cycle's loops.
func TestTheWatcherGivesUpOnARefusedConfiguration(t *testing.T) {
	t.Setenv(fakeAnchorctlStatusEnv, "none")

	s, log := supervised(t, "1")

	// A configuration conflux refuses, written under the running service.
	if err := os.WriteFile(s.Dirs.ConfigFile(), []byte(`{"version":1,"mode":"neither"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	gaveUp := make(chan bool, 1)
	go func() {
		gaveUp <- s.watch(t.Context(), &config.Config{Mode: config.ModeProxy}, brought{anchor: true}, time.Millisecond)
	}()

	select {
	case got := <-gaveUp:
		if !got {
			t.Fatal("the watch ended without giving up")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the watcher went on rebuilding an anchor its configuration refuses")
	}

	b, _ := os.ReadFile(log)
	if stops := strings.Count(string(b), "stop\n"); stops != rebuildRefusals {
		t.Errorf("rebuilt %d times before giving up, want %d", stops, rebuildRefusals)
	}
}

// TestEachIsGivenUpOnAlone: the anchor or the observer refused for good rebuildRefusals times in
// a row is given up on alone -- tried no more, while the watch goes on keeping the other, and
// with it the renewal timer, which a watch that gives up ends -- and the watch gives up only once
// both are given up on.
func TestEachIsGivenUpOnAlone(t *testing.T) {
	for name, tc := range map[string]struct {
		status, observer, capture string
		gaveUp                    bool
		rebuilds, observes        int
	}{
		"an anchor beside an observer observing": {status: "none", observer: "running", rebuilds: rebuildRefusals},
		"an anchor beside an observer refused too": {status: "none", observer: "failed", capture: "1", gaveUp: true,
			rebuilds: rebuildRefusals, observes: rebuildRefusals},
		"an observer beside an anchor running": {status: "running", observer: "failed", capture: "1", observes: rebuildRefusals},
	} {
		t.Run(name, func(t *testing.T) {
			t.Setenv(fakeAnchorctlStatusEnv, tc.status)
			t.Setenv(fakeAnchorctlObserverEnv, tc.observer)
			t.Setenv(fakeAnchorctlCaptureEnv, tc.capture)
			t.Setenv(fakeAnchorctlRefuseEnv, "start")

			s, log := supervised(t, "1")

			cfg := &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}, Observer: &config.Observer{}}
			if err := config.Save(s.Dirs, cfg); err != nil {
				t.Fatal(err)
			}

			credentialed(t, s.Dirs)

			ctx, cancel := context.WithTimeout(t.Context(), 500*time.Millisecond)
			defer cancel()

			if got := s.watch(ctx, cfg, brought{anchor: true, observing: true}, time.Millisecond); got != tc.gaveUp {
				t.Errorf("the watch gave up %v, want %v", got, tc.gaveUp)
			}

			cmds := strings.Join(ran(t, log), "\n")

			if n := strings.Count(cmds, "start"); n != tc.rebuilds {
				t.Errorf("the anchor was rebuilt %d times, want %d", n, tc.rebuilds)
			}

			if n := strings.Count(cmds, "observe"); n != tc.observes {
				t.Errorf("the observer was started %d times, want %d", n, tc.observes)
			}

			// Given up on, the anchor's refusal is recorded for status.
			st, err := config.LoadState(s.Dirs)
			if err != nil {
				t.Fatal(err)
			}

			if recorded := strings.Contains(st.AnchorRefused, "TUN device") && !st.AnchorRefusedAt.IsZero(); recorded != (tc.rebuilds > 0) {
				t.Errorf("the state records the anchor refused as %q at %v, want recorded %v", st.AnchorRefused, st.AnchorRefusedAt, tc.rebuilds > 0)
			}
		})
	}
}

// TestAGoneAnchorDirectoryIsTheNextSpawnsToMake: an anchor directory gone from under the running
// service is made again by the next spawn, as the identity anchord is given, rather than by a
// rebuild, which would make it the supervisor's: an account's anchord could not write it, and
// the next start would take it for conflux 1.0.0's and refuse the machine for good.
func TestAGoneAnchorDirectoryIsTheNextSpawnsToMake(t *testing.T) {
	t.Setenv(fakeAnchorctlStatusEnv, "none")

	s, log := supervised(t, "1")
	s.respawn = make(chan struct{}, 1)

	credentialed(t, s.Dirs)

	if err := os.RemoveAll(s.priv.Dir); err != nil {
		t.Fatal(err)
	}

	if got := s.rebuildAnchor(t.Context(), "anchord holds no anchor any more", false, newKeeper(time.Millisecond, time.Millisecond)); got != respawned {
		t.Errorf("the rebuild came to %v, want the cycle asked to start anchord again", got)
	}

	select {
	case <-s.respawn:
	default:
		t.Error("the cycle was not asked to start anchord again")
	}

	if exists(s.priv.Dir) {
		t.Errorf("the rebuild made %s itself", s.priv.Dir)
	}

	if slices.Contains(ran(t, log), "start") {
		t.Error("an anchor was started with no directory to start it in")
	}
}

// TestAWholeStartTriesTheAnchorAfresh: a bring-up of everything the configuration runs -- the
// cycle's, at every start of the daemon -- tries the anchor afresh, so the record of one the
// supervisor gave up on before goes before anything starts, whatever the start then comes to:
// an anchor up, one not up yet or refused for good, beside an observer or with none, none at all
// observing alone. A start records nothing of its own: the supervisor gives up on the anchor
// only where it stops trying it.
func TestAWholeStartTriesTheAnchorAfresh(t *testing.T) {
	observer := &config.Observer{}

	for name, tc := range map[string]struct {
		mode     config.Mode
		observer *config.Observer
		refusing string // the stand-in's refusal of the anchor's start, where it refuses one
	}{
		"an anchor that comes up":             {config.ModeProxy, observer, ""},
		"an anchor that does not come up yet": {config.ModeProxy, observer, fakeAnchorctlFailEnv},
		"an anchor refused for good":          {config.ModeProxy, observer, fakeAnchorctlRefuseEnv},
		"refused for good with no observer":   {config.ModeProxy, nil, fakeAnchorctlRefuseEnv},
		"observing alone":                     {config.ModeObserve, observer, ""},
	} {
		t.Run(name, func(t *testing.T) {
			if tc.refusing != "" {
				t.Setenv(tc.refusing, "start")
			}

			d := benchSite(t)

			cfg := configOf(t, d)
			cfg.Mode, cfg.Observer = tc.mode, tc.observer

			if err := config.Save(d, cfg); err != nil {
				t.Fatal(err)
			}

			givenUp(t, d)

			_, err := bringUp(t.Context(), d, fakeCtl(t), nopReporter{}, d.RootAnchorDir(), false, everything(cfg))
			if (err != nil) != (tc.refusing != "") {
				t.Fatalf("bringUp = %v, with the anchor's start refused %v", err, tc.refusing != "")
			}

			if st, err := config.LoadState(d); err != nil || st.AnchorRefused != "" || !st.AnchorRefusedAt.IsZero() {
				t.Errorf("a whole start left the anchor recorded as given up on: %q at %v (%v)", st.AnchorRefused, st.AnchorRefusedAt, err)
			}
		})
	}
}

// TestARebuiltAnchorIsNotGivenUpOn: an anchor recorded as given up on that the watcher's rebuild
// brings up after all, beside the observer, is not recorded so any more: status says it only
// while it holds.
func TestARebuiltAnchorIsNotGivenUpOn(t *testing.T) {
	t.Setenv(fakeAnchorctlStatusEnv, "none")
	t.Setenv(fakeAnchorctlObserverEnv, "running")

	s, _ := supervised(t, "1")

	if err := config.Save(s.Dirs, &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}, Observer: &config.Observer{}}); err != nil {
		t.Fatal(err)
	}

	credentialed(t, s.Dirs)
	givenUp(t, s.Dirs)

	if got := s.rebuildAnchor(t.Context(), "anchord holds no anchor any more", false, newKeeper(time.Millisecond, time.Millisecond)); got != kept {
		t.Fatalf("the rebuild came to %v, want the anchor back", got)
	}

	if st, err := config.LoadState(s.Dirs); err != nil || st.AnchorRefused != "" || !st.AnchorRefusedAt.IsZero() {
		t.Errorf("an anchor came up, and the state still records it given up on: %q at %v (%v)", st.AnchorRefused, st.AnchorRefusedAt, err)
	}
}

// givenUp records in d's state, keeping the rest of it, an anchor the supervisor gave up on an
// hour ago.
func givenUp(t *testing.T, d paths.Dirs) {
	t.Helper()

	st, err := config.LoadState(d)
	if err != nil {
		t.Fatal(err)
	}

	st.AnchorRefused, st.AnchorRefusedAt = "an earlier refusal", time.Now().Add(-time.Hour).UTC()
	if err := config.SaveState(d, st); err != nil {
		t.Fatal(err)
	}
}

// TestTheTailHoldsTheLastWords: the output of a daemon that dies straight after
// writing is still in the tail by the time its exit is reported. Draining the pipes
// beside Wait, rather than through it, lost exactly this line.
func TestTheTailHoldsTheLastWords(t *testing.T) {
	s, _ := supervised(t, "1")

	_, c, err := s.spawn(t.Context())
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}

	if <-c.exited; c.err == nil {
		t.Fatal("the stand-in anchord exited 0")
	}

	if tail := s.tail.String(); !strings.Contains(tail, fakeAnchordLastWords) || !strings.Contains(tail, "anchord starting") {
		t.Errorf("the tail lost anchord's output:\n%s", tail)
	}
}

func TestLineWriter(t *testing.T) {
	var got []string

	w := &lineWriter{emit: func(l string) { got = append(got, l) }}

	for _, chunk := range []string{"one\ntw", "o\r\nthr", "ee"} {
		if _, err := w.Write([]byte(chunk)); err != nil {
			t.Fatal(err)
		}
	}

	w.flush()

	if want := []string{"one", "two", "three"}; !slices.Equal(got, want) {
		t.Errorf("lines = %q, want %q", got, want)
	}

	got = nil

	_, _ = w.Write([]byte(strings.Repeat("x", maxLine+1)))

	if len(got) != 1 || len(got[0]) != maxLine+1 {
		t.Errorf("a line with no end was held rather than read out: %d lines", len(got))
	}
}

// TestAReopenedLinkIsCounted: an uplink found dead and rebuilt is counted, in the state the
// bring-up writes, for status to show; a rebuild that is not one is not.
func TestAReopenedLinkIsCounted(t *testing.T) {
	d := benchSite(t)
	ctl := fakeCtl(t)

	for _, reopened := range []bool{false, true, true} {
		if _, err := bringUp(t.Context(), d, ctl, nopReporter{}, d.RootAnchorDir(), reopened, parts{anchor: true}); err != nil {
			t.Fatal(err)
		}
	}

	st, err := config.LoadState(d)
	if err != nil {
		t.Fatal(err)
	}

	if st.LinkReopens != 2 || st.LastLinkReopen.IsZero() {
		t.Errorf("after two reopens the state says %d, last %v", st.LinkReopens, st.LastLinkReopen)
	}
}

// observingAlone saves cfg, observing alone in the taint supervised configures, with a current
// credential to observe under: what the watcher's restart of an observer starts it on.
func observingAlone(t *testing.T, d paths.Dirs, cfg *config.Config) {
	t.Helper()

	cfg.Taints = []string{"t"}
	if err := config.Save(d, cfg); err != nil {
		t.Fatal(err)
	}

	credentialed(t, d)
}

// TestACorruptStateRefusesTheStart: a state.json that does not parse stops the start for good,
// naming the file, whatever the configuration runs -- an anchor, the observer alone, or both,
// each under the credential the state describes -- and is left as it was for the operator to
// repair or delete, never replaced by an empty one, which would lose the AnchorID it held.
func TestACorruptStateRefusesTheStart(t *testing.T) {
	for name, cfg := range map[string]*config.Config{
		"an anchor":          {Mode: config.ModeProxy, Taints: []string{"bench"}},
		"the observer alone": {Mode: config.ModeObserve, Observer: &config.Observer{}, Taints: []string{"bench"}},
		"both":               {Mode: config.ModeProxy, Observer: &config.Observer{}, Taints: []string{"bench"}},
	} {
		t.Run(name, func(t *testing.T) {
			d := benchSite(t)

			if err := config.Save(d, cfg); err != nil {
				t.Fatal(err)
			}

			corrupt := []byte(`{"anchorId": "` + fakeAnchorID)
			if err := os.WriteFile(d.StateFile(), corrupt, 0o600); err != nil {
				t.Fatal(err)
			}

			_, err := bringUp(t.Context(), d, fakeCtl(t), nopReporter{}, d.RootAnchorDir(), false, everything(cfg))

			switch {
			case err == nil:
				t.Fatal("it came up on a corrupt state.json")
			case !Permanent(err):
				t.Errorf("a corrupt state.json is retried, though no retry changes it: %v", err)
			case !strings.Contains(err.Error(), d.StateFile()):
				t.Errorf("the refusal does not name %s: %v", d.StateFile(), err)
			}

			if b, _ := os.ReadFile(d.StateFile()); string(b) != string(corrupt) {
				t.Errorf("the corrupt state.json was rewritten as %q", b)
			}
		})
	}
}

// TestTheWatcherStartsAFailedObserverAgain: an observer whose capture ended is started
// again; one stopped by hand, or never started, is left as it is.
func TestTheWatcherStartsAFailedObserverAgain(t *testing.T) {
	t.Setenv(fakeAnchorctlStatusEnv, "none")

	cfg := &config.Config{Mode: config.ModeObserve, Observer: &config.Observer{}}

	for row, want := range map[string]bool{"failed": true, "stopped": false, "running": false} {
		t.Run(row, func(t *testing.T) {
			t.Setenv(fakeAnchorctlObserverEnv, row)

			s, log := supervised(t, "1")
			observingAlone(t, s.Dirs, cfg)

			ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
			defer cancel()

			s.watch(ctx, cfg, brought{observing: true}, time.Millisecond)

			if got := slices.Contains(ran(t, log), "observe"); got != want {
				t.Errorf("an observer that is %s: started again %v, want %v", row, got, want)
			}
		})
	}
}

// TestTheWatcherGivesUpOnAnObserverTheHostRefuses: observing alone, an observer the host
// will not let capture is started again rebuildRefusals times and then given up on, which
// ends the cycle's loops, rather than every thirty seconds for ever.
func TestTheWatcherGivesUpOnAnObserverTheHostRefuses(t *testing.T) {
	t.Setenv(fakeAnchorctlStatusEnv, "none")
	t.Setenv(fakeAnchorctlObserverEnv, "failed")
	t.Setenv(fakeAnchorctlCaptureEnv, "1")

	s, log := supervised(t, "1")
	cfg := &config.Config{Mode: config.ModeObserve, Observer: &config.Observer{}}
	observingAlone(t, s.Dirs, cfg)

	gaveUp := make(chan bool, 1)
	go func() { gaveUp <- s.watch(t.Context(), cfg, brought{observing: true}, time.Millisecond) }()

	select {
	case got := <-gaveUp:
		if !got {
			t.Fatal("the watch ended without giving up")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the watcher went on starting an observer the host refuses")
	}

	if n := strings.Count(strings.Join(ran(t, log), "\n"), "observe"); n != rebuildRefusals {
		t.Errorf("started %d times before giving up, want %d", n, rebuildRefusals)
	}
}

// TestASwitchedOffFarEndIsReopenedLessAndLessOften: a link whose every rebuild works and none
// of which brings a connection -- a far end switched off -- is a rebuild that failed each time,
// so the watcher reopens it less and less often rather than at every grace period for ever.
func TestASwitchedOffFarEndIsReopenedLessAndLessOften(t *testing.T) {
	t.Setenv(fakeAnchorctlStatusEnv, "running")
	t.Setenv(fakeAnchorctlIdleEnv, "1")

	grace := linkGrace
	linkGrace = 20 * time.Millisecond

	t.Cleanup(func() { linkGrace = grace })

	s, log := supervised(t, "1")

	device := filepath.Join(t.TempDir(), "ttyUSB0")
	if err := os.WriteFile(device, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}, Uplink: device}
	if err := config.Save(s.Dirs, cfg); err != nil {
		t.Fatal(err)
	}

	credentialed(t, s.Dirs)

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()

	if s.watch(ctx, cfg, brought{anchor: true}, time.Millisecond) {
		t.Fatal("the watcher gave up on a link it can rebuild")
	}

	// Each rebuild stops the anchor first. Reopened at every grace period, that is one every
	// 20ms or so; backing off from a millisecond, a dozen at most in two seconds.
	if n := strings.Count(strings.Join(ran(t, log), "\n"), "stop"); n < 2 || n > 12 {
		t.Errorf("reopened the link %d times in two seconds, want it reopened, less and less often", n)
	}
}

// TestALinkThatCarriesHasWorked: a rebuilt link that then carries something has worked, so found
// ended again later it is rebuilt as any ended link is, rather than taken for a rebuild that
// brought nothing and held off for the backoff.
func TestALinkThatCarriesHasWorked(t *testing.T) {
	t.Setenv(fakeAnchorctlStatusEnv, "running")
	t.Setenv(fakeAnchorctlIdleEnv, "1")

	grace := linkGrace
	linkGrace = 300 * time.Millisecond

	t.Cleanup(func() { linkGrace = grace })

	s, log := supervised(t, "1")

	r := &recorder{}
	s.Reporter = r

	device := filepath.Join(t.TempDir(), "ttyUSB0")
	if err := os.WriteFile(device, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}, Uplink: device}
	if err := config.Save(s.Dirs, cfg); err != nil {
		t.Fatal(err)
	}

	credentialed(t, s.Dirs)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})

	go func() {
		s.watch(ctx, cfg, brought{anchor: true}, time.Millisecond)
		close(done)
	}()

	defer func() {
		cancel()
		<-done
	}()

	count := func(cmd string) int {
		n := 0

		for _, c := range ran(t, log) {
			if c == cmd {
				n++
			}
		}

		return n
	}

	eventually(t, "the idle link rebuilt", func() bool { return count("start") == 1 })

	// Carrying something, inside the grace the rebuilt link is given: looked at twice, so at
	// least once by a stand-in started after the change.
	t.Setenv(fakeAnchorctlIdleEnv, "")

	looked := count("metrics")
	eventually(t, "the link seen carrying", func() bool { return count("metrics") >= looked+2 })

	t.Setenv(fakeAnchorctlIdleEnv, "1")
	eventually(t, "the link rebuilt once it ended again", func() bool { return count("start") == 2 })

	if _, warns := r.said(); slices.ContainsFunc(warns, func(w string) bool { return strings.Contains(w, "carried nothing since it was rebuilt") }) {
		t.Errorf("a link that carried something was taken for one that brought nothing: %q", warns)
	}
}

// TestAnObserverThatDidNotStartBesideAnAnchorIsStartedAgain: beside an anchor, an observer whose
// start failed is the watcher's to start again, as one whose capture ended is, rather than left
// for the daemon's life because status reads it as one never started.
func TestAnObserverThatDidNotStartBesideAnAnchorIsStartedAgain(t *testing.T) {
	t.Setenv(fakeAnchorctlStatusEnv, "running")
	t.Setenv(fakeAnchorctlFailEnv, "observe")

	s, log := supervised(t, "1")

	cfg := &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}, Observer: &config.Observer{}}
	if err := config.Save(s.Dirs, cfg); err != nil {
		t.Fatal(err)
	}

	credentialed(t, s.Dirs)

	up, err := s.bringUpAll(t.Context(), cfg)
	if err != nil || !up.anchor || up.observing {
		t.Fatalf("the bring-up = %+v, %v; want the anchor up and the observer not", up, err)
	}

	t.Setenv(fakeAnchorctlFailEnv, "")

	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()

	s.watch(ctx, cfg, up, time.Millisecond)

	if n := strings.Count(strings.Join(ran(t, log), "\n"), "observe"); n != 2 {
		t.Errorf("the observer was started %d times, want once by the bring-up and once by the watcher", n)
	}
}

// TestAGoneDeviceIsWaitedFor: nothing can be built on a device that has left the filesystem,
// so the anchor on it is stopped once and nothing more is tried -- no bring-up, no state written
// -- until the device is back, when the anchor is rebuilt on it and the reopen counted.
func TestAGoneDeviceIsWaitedFor(t *testing.T) {
	t.Setenv(fakeAnchorctlStatusEnv, "running")

	s, log := supervised(t, "1")

	device := filepath.Join(t.TempDir(), "ttyUSB0")

	cfg := &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}, Uplink: device}
	if err := config.Save(s.Dirs, cfg); err != nil {
		t.Fatal(err)
	}

	credentialed(t, s.Dirs)

	// An anchor that was up, as the bring-up said.
	if err := MarkReady(s.Dirs, fakeAnchorID); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})

	go func() {
		s.watch(ctx, cfg, brought{anchor: true}, time.Millisecond)
		close(done)
	}()

	defer func() {
		cancel()
		<-done
	}()

	eventually(t, "the anchor on the gone device stopped", func() bool { return slices.Contains(ran(t, log), "stop") })

	if IsReady(s.Dirs) {
		t.Error("the readiness marker still says an anchor is up, with the anchor stopped")
	}

	time.Sleep(200 * time.Millisecond)

	if cmds := ran(t, log); slices.Contains(cmds, "start") || len(cmds) != 1 {
		t.Errorf("anchorctl ran %v with the device gone; want the one stop", cmds)
	}

	if _, err := os.Stat(s.Dirs.StateFile()); err == nil {
		t.Error("the state was written with the device gone")
	}

	if err := os.WriteFile(device, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	// Counted in the state the bring-up writes once anchorctl's start has answered.
	eventually(t, "the anchor rebuilt on the device back, and the reopen counted", func() bool {
		st, err := config.LoadState(s.Dirs)

		return err == nil && st.LinkReopens > 0
	})

	if st, _ := config.LoadState(s.Dirs); st.LinkReopens != 1 || !slices.Contains(ran(t, log), "start") {
		t.Errorf("the state counts %d reopens, and anchorctl ran %v; want the one reopen, started", st.LinkReopens, ran(t, log))
	}
}
