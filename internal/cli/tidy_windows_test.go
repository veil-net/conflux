package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/pathstest"
	"github.com/veil-net/conflux/internal/privcheck"
	"github.com/veil-net/conflux/internal/privtest"
	"github.com/veil-net/conflux/internal/service"
)

// olderRoot is an installation's root as an older conflux left it on a Windows client, where what an
// elevated administrator makes is that administrator's own (privtest.CreatorOwns): logs\, the two lock
// files, bin\ with this build's set in it -- planted by whoever held a handle on bin\ then, its
// binaries padded to their sizes, which a start took as whole -- and the service's copy of conflux,
// each the administrator's, beside a configuration the update keeps. It returns them, and the plant.
func olderRoot(t *testing.T) (d paths.Dirs, old []string, plant map[string][]byte) {
	t.Helper()

	d = pathstest.Dirs(t)

	if err := config.Save(d, &config.Config{Mode: config.ModeProxy, Proxies: []string{"8080=127.0.0.1:3000"},
		Taints: []string{"cfx-old"}}); err != nil {
		t.Fatal(err)
	}

	set := filepath.Join(d.Libexec(), anchor.SetID())
	plant = map[string][]byte{
		filepath.Join(set, "anchord.exe"):   anchor.Anchord(),
		filepath.Join(set, "anchorctl.exe"): anchor.Anchorctl(),
	}

	restore := privtest.CreatorOwns(t)

	if err := os.RemoveAll(d.Log); err != nil {
		t.Fatal(err)
	}

	for _, dir := range []string{d.Log, set} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	files := map[string][]byte{d.LockFile(): nil, d.ServeLockFile(): nil, d.ServiceExecutable(): []byte("an older conflux")}
	for p, want := range plant {
		files[p] = make([]byte, len(want))
	}

	for p, body := range files {
		if err := os.WriteFile(p, body, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	restore()

	old = []string{d.Log, d.LockFile(), d.ServeLockFile(), d.Libexec(), d.ServiceExecutable()}

	for _, p := range old {
		if privtest.ReadSecurity(t, p).Owner.Equals(privtest.Admins) {
			t.Fatalf("%s, made under a client's policy, is the Administrators' already", p)
		}
	}

	return d, old, plant
}

// TestUpdateRemakesWhatAnOlderConfluxLeft: the conflux an update puts in place, handed the service
// through its start (the anchor running) or its register (stopped), removes what an older conflux left
// in the root as the administrator's own -- logs\, the lock files, bin\ with the set planted in it, the
// service's copy -- before anything judges the root, and makes each afresh: what is there once it is
// done is the Administrators', the plant is gone and this build's pair is in its place, and the lock
// files, which nothing holds, are gone for whatever next takes them to make again. It says what it
// removed. That the service's judgement then takes the root is paths' client test's
// (TestAnUpdatedOlderRootIsOneTheServiceTakes). Windows-only, so it runs in CI's platforms job alone.
func TestUpdateRemakesWhatAnOlderConfluxLeft(t *testing.T) {
	anchortest.Require(t)

	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	for _, verb := range []string{"start", "register"} {
		t.Run(verb, func(t *testing.T) {
			d, old, plant := olderRoot(t)

			mgr := &fakeManager{d: d, restartErr: errStartsNothing}
			standInService(t, mgr)

			out, errOut, code := capture(t, verb)
			if len(mgr.installs) != 1 || (verb == "register") != (code == ExitOK) {
				t.Fatalf("conflux %s exited %d and registered the service %d times:\n%s%s", verb, code, len(mgr.installs),
					out, errOut)
			}

			for p, want := range plant {
				if b, err := os.ReadFile(p); err != nil || !bytes.Equal(b, want) {
					t.Errorf("%s is still the plant, or not this build's (%d bytes, %v)", p, len(b), err)
				}
			}

			for _, p := range []string{d.Log, d.Libexec(), d.ServiceExecutable()} {
				if owner := privtest.ReadSecurity(t, p).Owner; !owner.Equals(privtest.Admins) {
					t.Errorf("%s belongs to %v once the update made it afresh, not the Administrators", p, owner)
				}
			}

			for _, p := range []string{d.LockFile(), d.ServeLockFile()} {
				if _, err := os.Lstat(p); !os.IsNotExist(err) {
					t.Errorf("%s, the administrator's and held by nothing, is still there (Lstat: %v)", p, err)
				}
			}

			for _, p := range old {
				if !strings.Contains(out, "  "+p+"\n") {
					t.Errorf("conflux %s did not say it removed %s:\n%s", verb, p, out)
				}
			}
		})
	}
}

// TestAPlainStartRemakesAnOlderRootWithTheServiceStopped: a start of the conflux the service already
// runs is no update and tidies nothing, but where no supervisor serves the root it removes what an
// older conflux left there as the administrator's own -- logs\, the lock files, bin\ with the set
// planted in it -- before anything judges the root, as tidy does, and EnsureAll makes logs\ again, the
// Administrators'; the plant is gone with bin\, for the next extraction to make afresh, and the
// service's copy, this conflux and the Administrators', stays. It says what it removed. With a
// supervisor serving the root the service has taken it already, so a start changes nothing of it.
// Windows-only, so it runs in CI's platforms job alone.
func TestAPlainStartRemakesAnOlderRootWithTheServiceStopped(t *testing.T) {
	anchortest.Require(t)

	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	d, old, plant := olderRoot(t)

	// The copy the service runs is this conflux, placed as an elevated conflux places it.
	if err := os.Remove(d.ServiceExecutable()); err != nil {
		t.Fatal(err)
	}

	if _, err := service.Place(d); err != nil {
		t.Fatal(err)
	}

	mgr := &fakeManager{d: d, restartErr: errStartsNothing}
	standInService(t, mgr)

	out, errOut, code := capture(t, "start")
	if code != ExitError || len(mgr.installs) != 1 || mgr.restarts != 1 {
		t.Fatalf("conflux start exited %d, registered %d times and restarted %d:\n%s%s", code, len(mgr.installs),
			mgr.restarts, out, errOut)
	}

	for p := range plant {
		if b, err := os.ReadFile(p); err == nil && !bytes.Equal(b, plant[p]) {
			t.Errorf("%s is still the plant", p)
		}
	}

	for _, p := range []string{d.Log, d.ServiceExecutable()} {
		if owner := privtest.ReadSecurity(t, p).Owner; !owner.Equals(privtest.Admins) {
			t.Errorf("%s belongs to %v once start made the root conflux's, not the Administrators", p, owner)
		}
	}

	for _, p := range []string{d.LockFile(), d.ServeLockFile()} {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("%s, the administrator's and held by nothing, is still there (Lstat: %v)", p, err)
		}
	}

	for _, p := range old {
		if p != d.ServiceExecutable() && !strings.Contains(out, "  "+p+"\n") {
			t.Errorf("conflux start did not say it removed %s:\n%s", p, out)
		}
	}
}
