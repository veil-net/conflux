package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/pathstest"
	"github.com/veil-net/conflux/internal/privcheck"
	"github.com/veil-net/conflux/internal/privtest"
)

// TestUpdateRemakesAnOldStyleRoot: on a Windows client an earlier conflux left bin\ the
// administrator's own, as that client's default-owner policy made it (privtest.CreatorOwns), and
// whoever held a handle on it then could plant this build's set in it, its binaries padded to their
// sizes, which a start took as whole. The conflux an update puts in place empties bin\ before it
// places anything, and extracts its pair afresh: the plant is gone, and what is there is the
// Administrators'. Windows-only, so it runs in CI's platforms job alone.
func TestUpdateRemakesAnOldStyleRoot(t *testing.T) {
	anchortest.Require(t)

	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	d := pathstest.Dirs(t)

	if err := config.Save(d, &config.Config{Mode: config.ModeProxy, Proxies: []string{"8080=127.0.0.1:3000"},
		Taints: []string{"cfx-old"}}); err != nil {
		t.Fatal(err)
	}

	set := filepath.Join(d.Libexec(), anchor.SetID())
	anchord, anchorctl := filepath.Join(set, "anchord.exe"), filepath.Join(set, "anchorctl.exe")

	restore := privtest.CreatorOwns(t)

	if err := os.MkdirAll(set, 0o700); err != nil {
		t.Fatal(err)
	}

	for p, n := range map[string]int{anchord: len(anchor.Anchord()), anchorctl: len(anchor.Anchorctl())} {
		if err := os.WriteFile(p, make([]byte, n), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	restore()

	if privtest.ReadSecurity(t, d.Libexec()).Owner.Equals(privtest.Admins) {
		t.Fatalf("%s, made under a client's policy, is the Administrators' already", d.Libexec())
	}

	mgr := &fakeManager{d: d}
	standInService(t, mgr)

	if out, errOut, code := capture(t, "register"); code != ExitOK || len(mgr.installs) != 1 {
		t.Fatalf("conflux register exited %d and registered %d times:\n%s%s", code, len(mgr.installs), out, errOut)
	}

	for p, want := range map[string][]byte{anchord: anchor.Anchord(), anchorctl: anchor.Anchorctl()} {
		if b, err := os.ReadFile(p); err != nil || !bytes.Equal(b, want) {
			t.Errorf("%s is still the plant, or not this build's (%d bytes, %v)", p, len(b), err)
		}
	}

	for _, p := range []string{d.Libexec(), set, anchord, anchorctl, d.ServiceExecutable()} {
		if owner := privtest.ReadSecurity(t, p).Owner; !owner.Equals(privtest.Admins) {
			t.Errorf("%s belongs to %v once the update made it afresh, not the Administrators", p, owner)
		}
	}
}
