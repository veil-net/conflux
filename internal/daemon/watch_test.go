package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/anchorctl"
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
// on. anchor redials an uplink every five seconds plus up to one of jitter, each dial
// with a 45s timeout, and the slowest line conflux accepts needs ~25s for a realm
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

	dead, reason, _ := s.linkIsDead(t.Context(), missing, &zeroSince)
	if !dead {
		t.Fatal("a device that is not there should be a dead link")
	}

	if reason == "" {
		t.Error("a dead link should say why")
	}
}

// TestBusyInterfaceIsPermanent: two conflux installations on one machine both default
// to anchor0, so this is the failure a second one hits every time. Retrying it to the
// unit's 90-second timeout leaves the reason in the journal and nothing but "job
// failed" in front of the operator.
func TestBusyInterfaceIsPermanent(t *testing.T) {
	err := &anchorctl.Error{
		Args:   []string{"start", "-tun=true", "-tun-name", "anchor0"},
		Stderr: `anchorctl: starting: anchor: opening anchor0: tundev: creating "anchor0": device or resource busy`,
	}

	if !isPermanent(err) {
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
			"tundev: creating \"anchor0\": operation not permitted\n" +
			"  a TUN needs IPv6 on the daemon's host, and CAP_NET_ADMIN on Linux, root on macOS and the BSDs, " +
			"Administrator and wintun.dll on Windows; give the daemon that, or start it in userspace mode"),
		"a host that will not forward": anchorctlSaid("anchorctl: starting: anchor: this host could not be set up to " +
			"forward for the realm: nft: command not found"),
		"a usage error": func() error {
			// The stand-in answers exit 2, anchorctl's usage error, to a status it was
			// not told how to give.
			t.Setenv(fakeAnchorctlStatusEnv, "")
			_, err := fakeCtl(t).Status(t.Context())

			return err
		}(),
	} {
		if !isPermanent(err) {
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
		if isPermanent(err) {
			t.Errorf("%s was treated as permanent; a retry can fix it", name)
		}
	}
}

// TestALostAnchorIsSeen: a daemon still answering with no anchor in it is rebuilt,
// unless it said an admin's kill order emptied it, and a daemon that does not answer
// is left to the restart loop. On a link the gauge is the poll, and status is asked
// only when the gauge cannot be read.
func TestALostAnchorIsSeen(t *testing.T) {
	for name, tc := range map[string]struct {
		status, failing string
		uplink, admin   bool
		want            string
	}{
		"an anchor running":                {status: "running"},
		"no anchor":                        {status: "none", want: "anchord holds no anchor any more"},
		"no anchor, after an admin's stop": {status: "none", admin: true, want: adminStopLine},
		"a daemon that does not answer":    {},
		"a link carrying something":        {uplink: true, status: "none"},
		"a link with no anchor behind it":  {uplink: true, status: "none", failing: "metrics", want: "anchord holds no anchor any more"},
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
			s.adminStopped.Store(tc.admin)

			var zeroSince time.Time

			if got, link := s.lost(t.Context(), uplink, devicePath(uplink), &zeroSince); got != tc.want || link {
				t.Errorf("lost() = %q, %v; want %q, false", got, link, tc.want)
			}
		})
	}
}

// TestTheAdminsStopIsHeard: the line anchord logs for a kill order is what tells the
// watcher to leave the anchor stopped, and a new daemon starts without it.
func TestTheAdminsStopIsHeard(t *testing.T) {
	s, _ := supervised(t, "1")

	s.lines().emit(`time=2026-10-04T09:00:00Z level=WARN msg="this anchor was stopped by an admin credential" by=anchorx reason=retired`)

	if !s.adminStopped.Load() {
		t.Fatal("the kill order's line was not noticed")
	}

	_, c, err := s.spawn(t.Context())
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}

	<-c.exited

	if s.adminStopped.Load() {
		t.Error("a new daemon inherited the last one's kill order")
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
