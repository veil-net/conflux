package cli

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/pathstest"
	"github.com/veil-net/conflux/internal/privcheck"
)

// installedScratch is a CONFLUX_DIR installation in a fresh directory, holding what one does once it
// has run: the configuration, the identity, the state with a given-up record in it, an extracted set
// and the service's copy of conflux, the lock files, the run directory's token, readiness marker and
// pid record, and an ephemeral run's root that a killed run left.
func installedScratch(t *testing.T) paths.Dirs {
	t.Helper()

	d := pathstest.Dirs(t)

	if err := config.Save(d, &config.Config{Mode: config.ModeProxy, Proxies: []string{"8080=127.0.0.1:3000"},
		Taints: []string{"cfx-scratch"}}); err != nil {
		t.Fatal(err)
	}

	if err := config.SaveManifest(d, config.Envelope("bWFuaWZlc3Q=")); err != nil {
		t.Fatal(err)
	}

	if err := config.SaveState(d, &config.State{AnchorID: "anchorscratch", AnchorRefused: "refused for good",
		AnchorRefusedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	for p, body := range map[string]string{
		filepath.Join(d.Libexec(), "0123456789abcdef", "anchord"): "an old set",
		filepath.Join(d.Libexec(), ".lock"):                       "",
		d.ServiceExecutable():                                     "the service's copy",
		d.LockFile():                                              "",
		d.ServeLockFile():                                         "",
		d.TokenFile():                                             "token",
		d.ReadyFile():                                             "ready",
		d.DaemonPIDFile():                                         "2147483646\n/nonexistent/anchord\n",
		filepath.Join(paths.EphemeralCandidates()[0], "serve.lock"): "",
	} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	return d
}

// TestUninstallLeavesNothingConfluxMade: uninstall removes everything conflux made, the identity,
// configuration and state included, and keeps nothing for a reinstall; and it removes what it finds
// there without following it. A link planted in a root -- to a directory outside it -- is removed as
// the link, and the directory it leads to, and what is in it, are untouched; a file planted there
// that another account owns is removed as itself. What an update left beside the conflux it
// replaced goes too, and that conflux stays, with whatever else is beside it: they are the
// operator's. It says what it removed. (On
// Windows, with a junction: the same test.)
func TestUninstallLeavesNothingConfluxMade(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	d := installedScratch(t)

	outside := t.TempDir()

	kept := filepath.Join(outside, "kept")
	if err := os.WriteFile(kept, []byte("not conflux's"), 0o600); err != nil {
		t.Fatal(err)
	}

	plantLink(t, filepath.Join(d.State, "planted-link"), outside)
	plantLink(t, filepath.Join(d.Libexec(), "0123456789abcdef", "planted-link"), outside)
	plantForeign(t, filepath.Join(d.State, "planted-foreign"))

	// The conflux an update replaced, with what that update left beside it.
	exe, leftovers, besideKept := updatedConflux(t)

	mgr := &fakeManager{d: d}
	standInService(t, mgr)

	out, errOut, code := capture(t, "uninstall", "--yes")
	if code != ExitOK {
		t.Fatalf("uninstall exited %d, saying:\n%s%s", code, out, errOut)
	}

	if _, err := os.Lstat(d.State); !os.IsNotExist(err) {
		var left []string

		_ = filepath.WalkDir(d.State, func(p string, _ fs.DirEntry, _ error) error {
			left = append(left, p)

			return nil
		})

		t.Errorf("uninstall left %s (Lstat: %v), holding:\n%s", d.State, err, strings.Join(left, "\n"))
	}

	if b, err := os.ReadFile(kept); err != nil || string(b) != "not conflux's" {
		t.Errorf("the directory a planted link led to lost what is in it: %q, %v", b, err)
	}

	for _, p := range leftovers {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("uninstall left %s, which an update left beside the conflux it replaced (Lstat: %v)", p, err)
		}
	}

	for _, p := range append(besideKept, exe) {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("uninstall removed %s, beside the conflux it was run as, which no update of it left: %v", p, err)
		}
	}

	for _, p := range append(leftovers, d.State) {
		if !strings.Contains(out, "  "+p+"\n") {
			t.Errorf("uninstall did not say it removed %s:\n%s", p, out)
		}
	}
}

// removing is the stand-in boot service, counting its removals and doing then as it is removed.
type removing struct {
	fakeManager

	removals int
	then     func()
}

func (m *removing) Remove() error {
	m.removals++

	if m.then != nil {
		m.then()
	}

	return nil
}

// TestUninstallLeavesALiveRun: an ephemeral run inside a CONFLUX_DIR would go with the root, so while
// one is live uninstall refuses, exit 2, naming it, before anything is asked or removed, as it does
// for one outside; and one that starts once uninstall has begun -- here as the boot service is
// removed -- is left running, with the root that holds it, and uninstall says so, exit 1.
func TestUninstallLeavesALiveRun(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	t.Run("live as uninstall begins", func(t *testing.T) {
		d := installedScratch(t)
		e := paths.EphemeralDirs(paths.EphemeralCandidates()[0])
		t.Cleanup(holdRoot(t, e))

		mgr := &removing{fakeManager: fakeManager{d: d}}
		standInService(t, mgr)

		out, errOut, code := capture(t, "uninstall", "--yes")
		if code != ExitUsage || !strings.Contains(errOut, e.State) {
			t.Errorf("uninstall beside a live run exited %d, want %d naming %s:\n%s%s", code, ExitUsage, e.State,
				out, errOut)
		}

		if _, err := os.Lstat(d.ConfigFile()); mgr.removals > 0 || err != nil {
			t.Errorf("uninstall beside a live run removed the boot service %d times, and %s (Lstat: %v)",
				mgr.removals, d.ConfigFile(), err)
		}
	})

	t.Run("started since", func(t *testing.T) {
		d := installedScratch(t)
		e := paths.EphemeralDirs(paths.EphemeralCandidates()[0])

		mgr := &removing{fakeManager: fakeManager{d: d}, then: func() { t.Cleanup(holdRoot(t, e)) }}
		standInService(t, mgr)

		out, errOut, code := capture(t, "uninstall", "--yes")
		if code != ExitError || !strings.Contains(errOut, e.State) || !strings.Contains(errOut, "left running") {
			t.Errorf("uninstall with a run started as it began exited %d, want %d naming %s, left running:\n%s%s",
				code, ExitError, e.State, out, errOut)
		}

		if _, err := os.Lstat(e.ServeLockFile()); err != nil {
			t.Errorf("uninstall removed the root of a live run: %v", err)
		}
	})
}

// TestARunTakingAKilledRunsRootKeepsIt: uninstall removes a killed run's root under its lock, as a
// run's own clean-up does, so a run that takes the root the moment the lock is let go of keeps it,
// and what it has put there: nothing removes the root again once its lock is let go of.
func TestARunTakingAKilledRunsRootKeepsIt(t *testing.T) {
	root := filepath.Join(t.TempDir(), "ephemeral")
	e := paths.EphemeralDirs(root)

	// This account's alone, as the test makes it.
	defer func(was func(string) error) { foreignRoot = was }(foreignRoot)
	foreignRoot = func(string) error { return nil }

	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(e.ServeLockFile(), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	// The run that takes the root as the killed run's lock is let go of, and what it puts there.
	taken := filepath.Join(root, "taken")

	was := removeEphemeral
	defer func() { removeEphemeral = was }()

	removeEphemeral = func(e paths.Dirs, unlock func(), r daemon.Reporter) error {
		return was(e, func() {
			unlock()

			if err := os.WriteFile(taken, []byte("a run's"), 0o600); err != nil {
				t.Error(err)
			}
		}, r)
	}

	if _, err := removeEphemeralRoot(root); err != nil {
		t.Fatalf("removeEphemeralRoot = %v", err)
	}

	if b, err := os.ReadFile(taken); err != nil || string(b) != "a run's" {
		t.Errorf("what a run put in the root it took as the killed run's lock was let go of is gone: %q, %v", b, err)
	}
}
