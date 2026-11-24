package cli

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/libexec"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/paths/pathstest"
)

// TestAPassThroughWithNothingRunningMakesNothing: on a machine with no daemon -- one never
// installed, or uninstalled -- a pass-through says so and leaves the disk as it found it,
// rather than extracting the anchor pair into directories uninstall removed.
func TestAPassThroughWithNothingRunningMakesNothing(t *testing.T) {
	root := filepath.Join(t.TempDir(), "conflux")
	t.Cleanup(paths.UseRoot(root))
	t.Setenv("ANCHOR_SOCKET", "")

	_, errOut, code := capture(t, "peers")

	if code != ExitUnavailable || !strings.Contains(errOut, "nothing is running here") {
		t.Errorf("conflux peers with nothing running exited %d:\n%s", code, errOut)
	}

	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Errorf("the pass-through made %s (%v); nothing should be on disk", root, err)
	}
}

// ranAnchorctl is the anchorctl a pass-through would have run, "" for none, and whether in
// place of conflux (anchorctlExec) rather than as its child (anchorctlRun).
type ranAnchorctl struct {
	bin     string
	inPlace bool
}

// stubAnchorctl replaces the pass-through's anchorctl for the test, and returns what it would
// have run.
func stubAnchorctl(t *testing.T) *ranAnchorctl {
	t.Helper()

	var ran ranAnchorctl

	wasExec, wasRun := anchorctlExec, anchorctlRun
	anchorctlExec = func(_ context.Context, bin string, _, _ []string) int { ran = ranAnchorctl{bin, true}; return ExitOK }
	anchorctlRun = func(bin string, _, _ []string) int { ran = ranAnchorctl{bin, false}; return ExitOK }

	t.Cleanup(func() { anchorctlExec, anchorctlRun = wasExec, wasRun })

	return &ran
}

// TestAPassThroughToANamedSocketMakesNothing: a daemon the user names, by ANCHOR_SOCKET or
// -socket, is not conflux's, so reaching it makes nothing of conflux's: no root, and no pair
// extracted into one.
func TestAPassThroughToANamedSocketMakesNothing(t *testing.T) {
	anchortest.Require(t)

	root := filepath.Join(t.TempDir(), "conflux")
	t.Cleanup(paths.UseRoot(root))
	t.Setenv("ANCHOR_SOCKET", filepath.Join(t.TempDir(), "theirs.sock"))

	ran := stubAnchorctl(t)

	if _, errOut, code := capture(t, "peers"); code != ExitOK || ran.bin == "" {
		t.Errorf("conflux peers to a named socket exited %d, running %q:\n%s", code, ran.bin, errOut)
	}

	if _, err := os.Stat(root); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a pass-through to a named socket made %s (%v); nothing should be on disk", root, err)
	}
}

// TestAPassThroughToANamedSocketReplacesConflux: a named socket's anchorctl runs in place of
// conflux, as every other pass-through's does, so what conflux is sent -- a SIGTERM, a SIGINT --
// reaches anchorctl: from a whole extraction, or from memory on Linux. Only a temporary copy,
// which conflux removes once anchorctl has finished with it, runs as conflux's child.
func TestAPassThroughToANamedSocketReplacesConflux(t *testing.T) {
	anchortest.Require(t)

	t.Setenv("ANCHOR_SOCKET", filepath.Join(t.TempDir(), "theirs.sock"))

	ran := stubAnchorctl(t)

	// Nothing extracted: from memory on Linux, and elsewhere a temporary copy.
	t.Cleanup(paths.UseRoot(filepath.Join(t.TempDir(), "conflux")))

	if _, errOut, code := capture(t, "peers"); code != ExitOK || ran.inPlace != (runtime.GOOS == "linux") {
		t.Errorf("conflux peers to a named socket, nothing extracted, on %s: exit %d, ran %+v:\n%s",
			runtime.GOOS, code, *ran, errOut)
	}

	tools, err := libexec.Ensure(pathstest.Root(t))
	if err != nil {
		t.Fatal(err)
	}

	*ran = ranAnchorctl{}

	if _, errOut, code := capture(t, "peers"); code != ExitOK || *ran != (ranAnchorctl{tools.Anchorctl, true}) {
		t.Errorf("conflux peers to a named socket, with a whole extraction: exit %d, ran %+v, want %s in place:\n%s",
			code, *ran, tools.Anchorctl, errOut)
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
		"peers --h":                    true,
		"block -h=true":                true,
		"block -target X -reason help": false,
		"peers":                        false,
	} {
		if got := wantsUsage(strings.Fields(args)); got != want {
			t.Errorf("wantsUsage(%q) = %v, want %v", args, got, want)
		}
	}
}

// TestRenewWithNoCredentialIsUnavailable: a machine configured but never enrolled, or
// enrolled and never started, has nothing to renew -- unavailable, as documented, not a
// failure.
func TestRenewWithNoCredentialIsUnavailable(t *testing.T) {
	d := pathstest.Root(t)

	if err := config.Save(d, &config.Config{Mode: config.ModeProxy, Taints: []string{"t"}}); err != nil {
		t.Fatal(err)
	}

	if code := renewNow(t.Context(), d); code != ExitUnavailable {
		t.Errorf("renew with no manifest exited %d, want %d", code, ExitUnavailable)
	}
}
