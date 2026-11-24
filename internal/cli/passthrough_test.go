package cli

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
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

// stubAnchorctl replaces the pass-through's anchorctl for the test, and returns where the one
// it would have run is: "" for none.
func stubAnchorctl(t *testing.T) *string {
	t.Helper()

	var ran string

	wasExec, wasRun := anchorctlExec, anchorctlRun
	anchorctlExec = func(_ context.Context, bin string, _, _ []string) int { ran = bin; return ExitOK }
	anchorctlRun = func(bin string, _, _ []string) int { ran = bin; return ExitOK }

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

	if _, errOut, code := capture(t, "peers"); code != ExitOK || *ran == "" {
		t.Errorf("conflux peers to a named socket exited %d, running %q:\n%s", code, *ran, errOut)
	}

	if _, err := os.Stat(root); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a pass-through to a named socket made %s (%v); nothing should be on disk", root, err)
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

// TestRenewWithNoCredentialIsUnavailable: a machine configured but never enrolled, or
// enrolled and never started, has nothing to renew -- unavailable, as documented, not a
// failure.
func TestRenewWithNoCredentialIsUnavailable(t *testing.T) {
	t.Cleanup(paths.UseRoot(t.TempDir()))

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
