package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/anchorctl"
	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/libexec"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/pathstest"
	"github.com/veil-net/conflux/internal/ui"
)

// TestAPassThroughWithNothingRunningMakesNothing: on a machine with no daemon -- one never
// installed, or uninstalled -- a pass-through says so and leaves the disk as it found it,
// rather than extracting the anchor pair into directories uninstall removed.
func TestAPassThroughWithNothingRunningMakesNothing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "conflux")
	t.Setenv("CONFLUX_DIR", root)
	t.Setenv(anchorctl.SocketEnv, "")

	_, errOut, code := capture(t, "peers")

	if code != ExitUnavailable || !strings.Contains(errOut, "nothing is running here") {
		t.Errorf("conflux peers with nothing running exited %d:\n%s", code, errOut)
	}

	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Errorf("the pass-through made %s (%v); nothing should be on disk", root, err)
	}
}

// TestAPassThroughToANamedSocketTakesTheReadersAnchorctl: a socket the user named, as -socket or
// ANCHOR_SOCKET, is a daemon conflux does not manage, which the installation never stands in the way of:
// its anchorctl is the readers' -- with no installation a temporary copy, removed, and nothing of
// conflux's made; with one whose roots pass the readers' check, this build's set, extracted into bin/
// where it is not there yet, and nothing written to the temporary directory; with a root the check
// refuses, a temporary copy, nothing extracted there -- and what it says is anchorctl's own dial to the
// socket named, which nothing listens on, never that nothing of conflux's runs.
func TestAPassThroughToANamedSocketTakesTheReadersAnchorctl(t *testing.T) {
	anchortest.Require(t)

	sock := filepath.Join(t.TempDir(), "sock")

	for name, tc := range map[string]struct {
		args []string
		env  string
	}{
		anchorctl.SocketEnv: {[]string{"peers"}, sock},
		"-socket":           {[]string{"peers", "-socket", sock}, ""},
	} {
		for _, root := range []string{"none", "installed", "refused"} {
			t.Run(fmt.Sprintf("%s, %s", name, root), func(t *testing.T) {
				conflux := filepath.Join(t.TempDir(), "conflux")
				t.Setenv("CONFLUX_DIR", conflux)
				t.Setenv(anchorctl.TokenEnv, "t")
				t.Setenv(anchorctl.SocketEnv, tc.env)

				tmp := pathstest.Temporary(t, t.TempDir())

				var d paths.Dirs
				if root != "none" {
					d = pathstest.DirsIn(t, conflux)
				}

				if root == "refused" {
					pathstest.NotAsConfluxMakesIt(t, d.State)
				}

				// Run as a child: on Unix a pass-through to conflux's own daemon replaces the process.
				if out, code := confluxChild(t, tc.args...); code == ExitOK || !strings.Contains(out, sock) {
					t.Errorf("conflux %s with %s=%s exited %d, not saying anchorctl could not reach %s:\n%s",
						strings.Join(tc.args, " "), anchorctl.SocketEnv, tc.env, code, sock, out)
				}

				if left, _ := os.ReadDir(tmp); len(left) > 0 {
					t.Errorf("the pass-through left %v in the temporary directory", left)
				}

				if root == "none" {
					if _, err := os.Stat(conflux); !os.IsNotExist(err) {
						t.Errorf("the pass-through made %s (%v); nothing should be on disk", conflux, err)
					}

					return
				}

				if _, err := libexec.Extracted(d); (err == nil) != (root == "installed") {
					t.Errorf("the pass-through, with a root %s, left this build's set in %s extracted %v (%v), want %v",
						root, d.Libexec(), err == nil, err, root == "installed")
				}
			})
		}
	}
}

// TestAnEmptySocketVariableIsUnset: ANCHOR_SOCKET and ANCHORD_TOKEN exported empty name
// nothing, so a pass-through reaches conflux's daemon as it does with neither set -- on Unix
// as well, where anchorctl replaces conflux and reads the first of two entries for a name.
func TestAnEmptySocketVariableIsUnset(t *testing.T) {
	anchortest.Require(t)

	d := pathstest.Dirs(t)
	looksRunning(t, d)

	t.Setenv(anchorctl.SocketEnv, "")
	t.Setenv(anchorctl.TokenEnv, "")

	// anchorctl's own answer: a dial to conflux's socket, which is a file nothing listens on.
	if out, code := confluxChild(t, "peers"); code == ExitOK || !strings.Contains(out, d.Socket()) {
		t.Errorf("conflux peers with %s and %s exported empty exited %d, and did not reach %s:\n%s",
			anchorctl.SocketEnv, anchorctl.TokenEnv, code, d.Socket(), out)
	}
}

// TestHelpIsACommandOrAFlag: usage reaches anchorctl with nothing running, and only a
// request for it does -- not the word help as some flag's value.
func TestHelpIsACommandOrAFlag(t *testing.T) {
	for args, want := range map[string]bool{
		"help":                         true,
		"help block":                   true,
		"block -h":                     true,
		"peers --help":                 true,
		"block -target X -reason help": false,
		"peers":                        false,
	} {
		if got := wantsUsage(strings.Fields(args)); got != want {
			t.Errorf("wantsUsage(%q) = %v, want %v", args, got, want)
		}
	}
}

// TestEveryHelpFlagIsHelp: each spelling Go's flag package answers with usage -- -h, --h,
// -help, --help, any of them with a value -- asks for usage wherever conflux reads one:
// renew prints its own rather than taking the flag for anchorctl's renew's, and a pass-through
// with nothing running reaches anchorctl's rather than being told nothing runs.
func TestEveryHelpFlagIsHelp(t *testing.T) {
	anchortest.Require(t)

	t.Setenv("CONFLUX_DIR", filepath.Join(t.TempDir(), "conflux"))
	t.Setenv(anchorctl.SocketEnv, "")

	// anchorctl's usage, which a pass-through prints to the terminal itself.
	devNull, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer devNull.Close()

	for _, h := range []string{"-h", "--h", "-help", "--help", "-h=x", "--help=x"} {
		if out, errOut, _ := capture(t, "renew", h); !strings.Contains(out, "conflux renew —") {
			t.Errorf("conflux renew %s did not print renew's usage; it said:\n%s", h, errOut)
		}

		stdout, stderr := os.Stdout, os.Stderr
		os.Stdout, os.Stderr = devNull, devNull
		_, errOut, code := capture(t, "peers", h)
		os.Stdout, os.Stderr = stdout, stderr

		if code != ExitOK {
			t.Errorf("conflux peers %s, with nothing running, exited %d rather than printing anchorctl's usage:\n%s", h, code, errOut)
		}
	}
}

// TestRenewWithNoCredentialIsUnavailable: a machine configured but never enrolled, or
// enrolled and never started, has nothing to renew -- unavailable, as documented, not a
// failure.
func TestRenewWithNoCredentialIsUnavailable(t *testing.T) {
	d := pathstest.Dirs(t)

	if err := config.Save(d, &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}}); err != nil {
		t.Fatal(err)
	}

	if code := renewNow(t.Context(), d); code != ExitUnavailable {
		t.Errorf("renew with no manifest exited %d, want %d", code, ExitUnavailable)
	}
}

// TestRenewCoversAMachineThatOnlyObserves: the observer runs under the machine's credential, so
// a machine that only observes has one to renew, and is answered as any other is: here, that a
// renewal is installed into what runs, and nothing does.
func TestRenewCoversAMachineThatOnlyObserves(t *testing.T) {
	d := pathstest.Dirs(t)

	if err := config.Save(d, &config.Config{Mode: config.ModeObserve, Observer: &config.Observer{}, Taints: []string{"t"}}); err != nil {
		t.Fatal(err)
	}

	if err := config.SaveManifest(d, config.Envelope("e30=")); err != nil {
		t.Fatal(err)
	}

	var errBuf bytes.Buffer

	old := ui.Errw
	ui.Errw = &errBuf

	t.Cleanup(func() { ui.Errw = old })

	code := renewNow(t.Context(), d)

	if said := errBuf.String(); code != ExitUnavailable || strings.Contains(said, "only observes") || !strings.Contains(said, "nothing is running") {
		t.Errorf("renew on a machine that only observes exited %d, saying:\n%s", code, said)
	}
}
