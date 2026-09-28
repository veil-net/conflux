package daemon

import (
	"os"
	"path/filepath"
	"runtime"
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
