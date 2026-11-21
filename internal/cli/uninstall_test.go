package cli

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/privcheck"
)

// TestUninstallLeavesNothingConfluxMade: uninstall removes everything conflux made, the identity,
// configuration and state included, and keeps nothing for a reinstall; and it removes what it finds
// there without following it. A link planted in a root -- to a directory outside it -- is removed as
// the link, and the directory it leads to, and what is in it, are untouched; a file planted there
// that another account owns is removed as itself. What an update left beside the conflux it
// replaced goes too, and that conflux stays, with whatever else is beside it: they are the
// operator's. What a dead supervisor and a killed run left running is stopped first. It says what it
// removed. (On
// Windows, with a junction: the same test.)
func TestUninstallLeavesNothingConfluxMade(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	old := oldInstall(t)
	d := old.d

	outside := t.TempDir()

	kept := filepath.Join(outside, "kept")
	if err := os.WriteFile(kept, []byte("not conflux's"), 0o600); err != nil {
		t.Fatal(err)
	}

	plantLink(t, filepath.Join(d.State, "planted-link"), outside)
	plantLink(t, filepath.Join(d.Libexec(), "0123456789abcdef", "planted-link"), outside)
	plantForeign(t, filepath.Join(d.State, "planted-foreign"))

	mgr := &fakeManager{d: d}
	standInService(t, mgr)

	accounts := recordAccounts(t)

	// What uninstall stops: the anchord a dead supervisor left, by the root's pid record, which passes
	// the readers' check; and the killed ephemeral run's, by its root's, inside the installation's.
	var reaped, emptied []string

	defer func(was func(paths.Dirs, time.Duration)) { reap = was }(reap)
	reap = func(d paths.Dirs, _ time.Duration) { reaped = append(reaped, d.State) }

	wasEmpty := removeEphemeral
	defer func() { removeEphemeral = wasEmpty }()

	removeEphemeral = func(e paths.Dirs, unlock func(), r daemon.Reporter) error {
		emptied = append(emptied, e.State)

		return wasEmpty(e, unlock, r)
	}

	out, errOut, code := capture(t, "uninstall", "--yes")
	if code != ExitOK {
		t.Fatalf("uninstall exited %d, saying:\n%s%s", code, out, errOut)
	}

	if !slices.Equal(*accounts, []bool{true}) {
		t.Errorf("uninstall removed the accounts anchord ran as %v, want once, the ephemeral run's with them", *accounts)
	}

	if !slices.Equal(reaped, []string{d.State}) || !slices.Equal(emptied, []string{paths.EphemeralCandidates()[0]}) {
		t.Errorf("uninstall reaped %q and emptied the ephemeral roots %q, want %s and the killed run's inside it, once each",
			reaped, emptied, d.State)
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

	for _, p := range old.leftovers {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("uninstall left %s, which an update left beside the conflux it replaced (Lstat: %v)", p, err)
		}
	}

	for _, p := range append(old.besideKept, old.exe) {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("uninstall removed %s, beside the conflux it was run as, which no update of it left: %v", p, err)
		}
	}

	for _, p := range append(old.leftovers, d.State) {
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

// recordAccounts records each removal of the accounts anchord ran as uninstall asks for, by whether the
// ephemeral run's account goes too, removing none.
func recordAccounts(t *testing.T) *[]bool {
	t.Helper()

	var asked []bool

	was := removeAccounts
	t.Cleanup(func() { removeAccounts = was })

	removeAccounts = func(ephemeral bool) error {
		asked = append(asked, ephemeral)

		return nil
	}

	return &asked
}

// TestUninstallLeavesALiveRun: an ephemeral run inside a CONFLUX_DIR would go with the root, so while
// one is live uninstall refuses, exit 2, naming it, before anything is asked or removed, as it does
// for one outside, and again once the question is answered, for one started as it was asked; and one
// that starts once uninstall has begun -- here as the boot service is removed -- is left running, with
// the root that holds it and the account it runs as, and uninstall says so, exit 1, listing what it
// removed all the same.
func TestUninstallLeavesALiveRun(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	t.Run("live as uninstall begins", func(t *testing.T) {
		d := oldInstall(t).d
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

	t.Run("live once asked", func(t *testing.T) {
		d := oldInstall(t).d
		e := paths.EphemeralDirs(paths.EphemeralCandidates()[0])

		defer func(was func(paths.Dirs, error, bool) bool) { confirm = was }(confirm)
		confirm = func(paths.Dirs, error, bool) bool {
			t.Cleanup(holdRoot(t, e))

			return true
		}

		mgr := &removing{fakeManager: fakeManager{d: d}}
		standInService(t, mgr)

		out, errOut, code := capture(t, "uninstall", "--yes")
		if code != ExitUsage || !strings.Contains(errOut, e.State) {
			t.Errorf("uninstall beside a run started as it asked exited %d, want %d naming %s:\n%s%s", code, ExitUsage,
				e.State, out, errOut)
		}

		if _, err := os.Lstat(d.ConfigFile()); mgr.removals > 0 || err != nil {
			t.Errorf("uninstall beside a run started as it asked removed the boot service %d times, and %s (Lstat: %v)",
				mgr.removals, d.ConfigFile(), err)
		}
	})

	t.Run("started since", func(t *testing.T) {
		d := oldInstall(t).d
		e := paths.EphemeralDirs(paths.EphemeralCandidates()[0])

		mgr := &removing{fakeManager: fakeManager{d: d}, then: func() { t.Cleanup(holdRoot(t, e)) }}
		standInService(t, mgr)

		accounts := recordAccounts(t)

		out, errOut, code := capture(t, "uninstall", "--yes")
		if code != ExitError || !strings.Contains(errOut, e.State) || !strings.Contains(errOut, "left running") {
			t.Errorf("uninstall with a run started as it began exited %d, want %d naming %s, left running:\n%s%s",
				code, ExitError, e.State, out, errOut)
		}

		if _, err := os.Lstat(e.ServeLockFile()); err != nil {
			t.Errorf("uninstall removed the root of a live run: %v", err)
		}

		if !strings.Contains(out, "  the boot service\n") {
			t.Errorf("uninstall, failing, did not say what it had removed:\n%s", out)
		}

		if !slices.Equal(*accounts, []bool{false}) {
			t.Errorf("uninstall removed the accounts anchord ran as %v, want once, the ephemeral run's kept", *accounts)
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

// TestUninstallRemovesTheSharedLog: the service's log, where the platform keeps it in the system's own
// log directory, outside conflux's roots -- /var/log on macOS and FreeBSD -- is removed with the one
// moved aside, and the directory, which is not conflux's, and whatever else is in it, are kept; a log
// directory inside a root goes with the root, and is not reached for here.
func TestUninstallRemovesTheSharedLog(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "conflux")

	for name, d := range map[string]paths.Dirs{
		"outside the roots": {Config: state, State: state, Run: filepath.Join(state, "run"), Log: filepath.Join(root, "log")},
		"inside a root":     {Config: state, State: state, Run: filepath.Join(state, "run"), Log: filepath.Join(state, "logs")},
	} {
		t.Run(name, func(t *testing.T) {
			other := filepath.Join(d.Log, "other.log")

			for _, p := range []string{d.LogFile(), d.LogFile() + ".1", other} {
				if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
					t.Fatal(err)
				}

				if err := os.WriteFile(p, []byte("a line"), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			if err := removeSharedLog(d); err != nil {
				t.Fatal(err)
			}

			outside := name == "outside the roots"

			for _, p := range []string{d.LogFile(), d.LogFile() + ".1"} {
				if _, err := os.Lstat(p); outside != errors.Is(err, fs.ErrNotExist) {
					t.Errorf("%s: %s (Lstat: %v), want it removed only outside the roots", name, p, err)
				}
			}

			if _, err := os.Lstat(other); err != nil {
				t.Errorf("%s: removed %s, which is not conflux's: %v", name, other, err)
			}
		})
	}
}
