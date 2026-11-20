package cli

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/ui"
)

// TestAPassThroughWithNothingRunningMakesNothing: on a machine with no daemon -- one never
// installed, or uninstalled -- a pass-through says so and leaves the disk as it found it,
// rather than extracting the anchor pair into directories uninstall removed.
func TestAPassThroughWithNothingRunningMakesNothing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "conflux")
	t.Setenv("CONFLUX_DIR", root)
	t.Setenv("ANCHOR_SOCKET", "")

	_, errOut, code := capture(t, "peers")

	if code != ExitUnavailable || !strings.Contains(errOut, "nothing is running here") {
		t.Errorf("conflux peers with nothing running exited %d:\n%s", code, errOut)
	}

	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Errorf("the pass-through made %s (%v); nothing should be on disk", root, err)
	}
}

// namedSocketArgs, set, makes TestAPassThroughToANamedSocketMakesNothing's test binary the
// conflux it runs: these arguments, one to a line.
const namedSocketArgs = "CONFLUX_TEST_NAMED_SOCKET_ARGS"

// TestAPassThroughToANamedSocketMakesNothing: a socket the user named, as -socket or
// ANCHOR_SOCKET, is a daemon conflux does not manage, so reaching it makes nothing of
// conflux's -- no directory, no extraction -- and an account that could not make them still
// reaches its own daemon.
func TestAPassThroughToANamedSocketMakesNothing(t *testing.T) {
	anchortest.Require(t)

	// Run as a child: on Unix a pass-through to conflux's own daemon replaces the process,
	// which here would be the test binary.
	if args := os.Getenv(namedSocketArgs); args != "" {
		os.Exit(Main(append([]string{"conflux"}, strings.Split(args, "\n")...)))
	}

	sock := filepath.Join(t.TempDir(), "sock")

	for name, tc := range map[string]struct {
		args []string
		env  string
	}{
		"ANCHOR_SOCKET": {[]string{"peers"}, "ANCHOR_SOCKET=" + sock},
		"-socket":       {[]string{"peers", "-socket", sock}, "ANCHOR_SOCKET="},
	} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "conflux")

			cmd := exec.Command(os.Args[0], "-test.run=^TestAPassThroughToANamedSocketMakesNothing$") //nolint:gosec // this test binary
			cmd.Env = append(os.Environ(), "CONFLUX_DIR="+root, "ANCHORD_TOKEN=t", tc.env,
				namedSocketArgs+"="+strings.Join(tc.args, "\n"))

			// anchorctl's own answer: a dial to the socket named, which nothing listens on.
			if out, err := cmd.CombinedOutput(); err == nil || !strings.Contains(string(out), sock) {
				t.Errorf("conflux %s with %s: %v\n%s", strings.Join(tc.args, " "), tc.env, err, out)
			}

			if _, err := os.Stat(root); !os.IsNotExist(err) {
				t.Errorf("the pass-through made %s (%v); nothing should be on disk", root, err)
			}
		})
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
	t.Setenv("ANCHOR_SOCKET", "")

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
	t.Setenv("CONFLUX_DIR", t.TempDir())

	d := paths.Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

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
	t.Setenv("CONFLUX_DIR", t.TempDir())

	d := paths.Default()
	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

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
