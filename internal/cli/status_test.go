package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/pathstest"
)

// runningStandIn makes d's daemon look running (looksRunning), and puts a stand-in anchorctl
// where d's extracted pair is found whole: a script that writes each command it is run with to a
// line of log, answers status with standInStatusEnv's line, or says an anchor runs, and says the
// export was set by a call to anchorctl export. Its anchord never runs. Each is padded to its
// embedded binary's size, which is what finding a pair whole checks.
func runningStandIn(t *testing.T, d paths.Dirs, log string) {
	t.Helper()

	dir := filepath.Join(d.Libexec(), anchor.SetID())
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}

	script := "#!/bin/sh\necho \"$1\" >>'" + log + "'\n" +
		"case $1 in\n" +
		"status) echo \"${" + standInStatusEnv + ":-anchor running}\" ;;\n" +
		"export) echo '  set by anchorctl export' ;;\n" +
		"esac\nexit 0\n"

	for path, f := range map[string]struct {
		content string
		size    int
	}{
		filepath.Join(dir, "anchorctl"): {script, len(anchor.Anchorctl())},
		filepath.Join(dir, "anchord"):   {"", len(anchor.Anchord())},
	} {
		writeScript(t, path, []byte(f.content), int64(f.size))
	}

	looksRunning(t, d)
}

// looksRunning makes d's daemon look running to status and the pass-through: its socket and its
// token there. Nothing listens on the socket.
func looksRunning(t *testing.T, d paths.Dirs) {
	t.Helper()

	if err := os.MkdirAll(d.DaemonRun(), 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(d.Socket(), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(d.TokenFile(), []byte("token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// standInStatusEnv is the line runningStandIn's anchorctl answers status with, where it is set.
const standInStatusEnv = "CONFLUX_TEST_STANDIN_STATUS"

// TestStatusSaysTheAnchorWasGivenUp: an anchor the supervisor gave up on, refused for good, is
// said on a `given up` line, with when and why and what tries again, wherever no anchor runs --
// the daemon answering with none, or not answering, the service having ended on it -- where
// anchorctl's status below says only that none runs. The line claims nothing of the observer,
// whose own row says whether it runs. Nothing of it is said while an anchor runs, nor observing
// alone.
func TestStatusSaysTheAnchorWasGivenUp(t *testing.T) {
	const why = "anchorctl: anchor: this host will not give this process a TUN device"

	at := time.Date(2026, 11, 20, 3, 0, 0, 0, time.UTC)
	line := "  given up     the anchor, at " + at.Format(time.RFC3339) + ": " + why + "\n" +
		strings.Repeat(" ", 15) + "conflux start tries the anchor again\n"

	for name, tc := range map[string]struct {
		mode   config.Mode
		daemon string // the stand-in's answer to status, or "" for no daemon answering
		said   bool
	}{
		"no daemon answering":            {config.ModeTUN, "", true},
		"a daemon holding no anchor":     {config.ModeTUN, "no anchor is running", true},
		"a daemon holding an anchor":     {config.ModeTUN, "anchor anchoraaaqeayeaudaocajbifqydiob4ibceqtcqkrmfyydenbwha5dypq", false},
		"observing alone, no daemon":     {config.ModeObserve, "", false},
		"observing alone, with a daemon": {config.ModeObserve, "no anchor is running", false},
	} {
		t.Run(name, func(t *testing.T) {
			d := pathstest.Dirs(t)

			if tc.daemon != "" {
				anchortest.Require(t)

				if runtime.GOOS == "windows" {
					t.Skip("the stand-in anchorctl is a shell script")
				}

				t.Setenv(standInStatusEnv, tc.daemon)
				runningStandIn(t, d, filepath.Join(t.TempDir(), "log"))
			}

			if err := config.Save(d, &config.Config{Mode: tc.mode, Observer: &config.Observer{}, Taints: []string{"t"}}); err != nil {
				t.Fatal(err)
			}

			if err := config.SaveState(d, &config.State{AnchorRefused: why, AnchorRefusedAt: at}); err != nil {
				t.Fatal(err)
			}

			out, errOut, code := capture(t, "status")
			if code != ExitOK {
				t.Fatalf("status exited %d:\n%s%s", code, out, errOut)
			}

			if tc.said && !strings.Contains(out, line) {
				t.Errorf("status should say\n%s\nit said:\n%s", line, out)
			}

			if !tc.said && (strings.Contains(out, "given up") || strings.Contains(out, why)) {
				t.Errorf("status said the anchor was given up on; it said:\n%s", out)
			}
		})
	}
}

// TestDownForgetsWhatWasGivenUp: an anchor stopped by hand is not one the supervisor gave up on,
// so `conflux down` clears the record, and status says nothing of it after.
func TestDownForgetsWhatWasGivenUp(t *testing.T) {
	rootOnLinux(t)

	d := pathstest.Dirs(t)

	if err := config.Save(d, &config.Config{Mode: config.ModeTUN, Observer: &config.Observer{}, Taints: []string{"t"}}); err != nil {
		t.Fatal(err)
	}

	if err := config.SaveState(d, &config.State{AnchorRefused: "refused", AnchorRefusedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	standInService(t, &fakeManager{d: d})

	if out, errOut, code := capture(t, "down"); code != ExitOK {
		t.Fatalf("down exited %d:\n%s%s", code, out, errOut)
	}

	if st, err := config.LoadState(d); err != nil || st.AnchorRefused != "" || !st.AnchorRefusedAt.IsZero() {
		t.Errorf("down left the anchor recorded as given up on: %q at %v (%v)", st.AnchorRefused, st.AnchorRefusedAt, err)
	}

	if out, _, _ := capture(t, "status"); strings.Contains(out, "given up") {
		t.Errorf("status after down said the anchor was given up on:\n%s", out)
	}
}
