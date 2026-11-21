package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/privcheck"
	"github.com/veil-net/conflux/internal/ui"
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

	plantLink(t, filepath.Join(d.State, ".tmp-planted-link"), outside)
	plantLink(t, filepath.Join(d.Libexec(), "0123456789abcdef", "planted-link"), outside)
	plantForeign(t, filepath.Join(d.State, ".tmp-planted-foreign"))

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
// and what it has put there: nothing removes the root again once its lock is let go of, and the root,
// still there, is not one uninstall says is gone.
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

	if gone, err := removeEphemeralRoot(root); gone || err != nil {
		t.Fatalf("removeEphemeralRoot = %v, %v, want the root a run took not gone", gone, err)
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

// TestUninstallLeavesARootHoldingWhatConfluxNeverMakes: a root conflux has not secured -- one at 0755 --
// holding a name conflux never makes there is not conflux's, so uninstall refuses it before it acts, exit
// 1, naming what it holds and saying it left everything in place, the boot service included -- not that
// another account may change the way to it -- and the root keeps what it holds.
func TestUninstallLeavesARootHoldingWhatConfluxNeverMakes(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	d := configured(t)

	stray := filepath.Join(d.State, "notes.txt")
	if err := os.WriteFile(stray, []byte("somebody's"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(d.State, 0o755); err != nil {
		t.Fatal(err)
	}

	mgr := &removing{fakeManager: fakeManager{d: d}}
	standInService(t, mgr)

	out, errOut, code := capture(t, "uninstall", "--yes")
	if code != ExitError || !strings.Contains(errOut, "notes.txt") || !strings.Contains(errOut, "left everything in place") ||
		strings.Contains(errOut, "Once nobody else can change") {
		t.Errorf("uninstall of a root holding what conflux never makes there exited %d, want %d naming it and "+
			"saying it left everything:\n%s%s", code, ExitError, out, errOut)
	}

	for _, p := range []string{stray, d.ConfigFile()} {
		if _, err := os.Lstat(p); err != nil || mgr.removals > 0 {
			t.Errorf("uninstall of a root holding what conflux never makes there removed the boot service %d times, "+
				"and %s (Lstat: %v)", mgr.removals, p, err)
		}
	}
}

// TestUninstallStopsWhereARootsWayCannotBeWalked: a CONFLUX_DIR beneath a file has a way conflux cannot
// walk, which is none of the refusals JudgeWays tells apart -- nobody else need be able to change
// anything for it -- so uninstall says it stopped there, before it acted, exit 1, the boot service not
// removed, and not that another account may change the way, nor that the root is shared or foreign; the
// file is left as it was.
func TestUninstallStopsWhereARootsWayCannotBeWalked(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, []byte("somebody's"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONFLUX_DIR", filepath.Join(file, "conflux"))

	mgr := &removing{fakeManager: fakeManager{d: paths.Default()}}
	standInService(t, mgr)

	out, errOut, code := capture(t, "uninstall", "--yes")
	if code != ExitError || !strings.Contains(errOut, "stopped there, before it acted") ||
		strings.Contains(errOut, "Once nobody else can change") || strings.Contains(errOut, "left everything in place") {
		t.Errorf("uninstall of a CONFLUX_DIR beneath a file exited %d, want %d saying it stopped before it acted:\n%s%s",
			code, ExitError, out, errOut)
	}

	if b, err := os.ReadFile(file); err != nil || string(b) != "somebody's" || mgr.removals > 0 {
		t.Errorf("uninstall of a CONFLUX_DIR beneath a file removed the boot service %d times, and left the file %q, "+
			"%v", mgr.removals, b, err)
	}
}

// TestUninstallAsksBeforeEmptyingAChosenFolder: uninstall empties a CONFLUX_DIR, a folder whoever set
// the variable chose, so it asks first whether or not an identity is there, and off a terminal without
// --yes refuses, exit 2, saying it would remove everything in that folder, with nothing removed.
func TestUninstallAsksBeforeEmptyingAChosenFolder(t *testing.T) {
	if ui.IsTerminal() {
		t.Skip("this test's stdin is a terminal")
	}

	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	d := configured(t)

	mgr := &removing{fakeManager: fakeManager{d: d}}
	standInService(t, mgr)

	out, errOut, code := capture(t, "uninstall")
	if code != ExitUsage || !strings.Contains(errOut, "removes everything in "+paths.Root()) ||
		!strings.Contains(errOut, "--yes") {
		t.Errorf("uninstall of a CONFLUX_DIR with no identity, off a terminal and without --yes, exited %d, want %d "+
			"saying it would remove everything in %s and naming --yes:\n%s%s", code, ExitUsage, paths.Root(), out, errOut)
	}

	if _, err := os.Lstat(d.ConfigFile()); err != nil || mgr.removals > 0 {
		t.Errorf("uninstall, unconfirmed, removed the boot service %d times, and %s (Lstat: %v)", mgr.removals,
			d.ConfigFile(), err)
	}
}

// TestUninstallSaysItRemovesTheCredentialInAChosenFolder: a CONFLUX_DIR holding an identity is a
// folder whoever set the variable chose, with the one copy of this machine's credential in it, so
// uninstall, off a terminal and without --yes, refuses, exit 2, saying it would remove everything in
// that folder, the credential among it, of which there is no other copy, with nothing removed.
func TestUninstallSaysItRemovesTheCredentialInAChosenFolder(t *testing.T) {
	if ui.IsTerminal() {
		t.Skip("this test's stdin is a terminal")
	}

	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	d := configured(t)

	if err := config.SaveManifest(d, config.Envelope("bWFuaWZlc3Q=")); err != nil {
		t.Fatal(err)
	}

	mgr := &removing{fakeManager: fakeManager{d: d}}
	standInService(t, mgr)

	want := "removes everything in " + paths.Root() + ", this machine's credential among it, and there is no other " +
		"copy of that"

	out, errOut, code := capture(t, "uninstall")
	if code != ExitUsage || !strings.Contains(errOut, want) || !strings.Contains(errOut, "--yes") {
		t.Errorf("uninstall of a CONFLUX_DIR holding an identity, off a terminal and without --yes, exited %d, want %d "+
			"saying it %s and naming --yes:\n%s%s", code, ExitUsage, want, out, errOut)
	}

	if _, err := os.Lstat(d.ManifestFile()); err != nil || mgr.removals > 0 {
		t.Errorf("uninstall, unconfirmed, removed the boot service %d times, and %s (Lstat: %v)", mgr.removals,
			d.ManifestFile(), err)
	}
}

// TestUninstallLeavesAFolderOfHomes: a CONFLUX_DIR pointed at a folder of homes, which holds alice/ and
// bob/ and nothing of conflux's, is not conflux's, so uninstall refuses it before it acts, asked or not
// -- the boot service not removed -- and both homes keep what they hold: at 0755, as /home is, and at
// 0700, as /root is, which conflux would secure a root at but which holds no installation's state.
func TestUninstallLeavesAFolderOfHomes(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	for _, c := range []struct {
		args []string
		mode os.FileMode
	}{{[]string{"uninstall", "--yes"}, 0o755}, {[]string{"uninstall"}, 0o755}, {[]string{"uninstall", "--yes"}, 0o700}} {
		args := c.args

		t.Run(fmt.Sprintf("%s at %#o", strings.Join(args, " "), c.mode), func(t *testing.T) {
			homes := t.TempDir()
			t.Setenv("CONFLUX_DIR", homes)

			if err := os.Chmod(homes, c.mode); err != nil {
				t.Fatal(err)
			}

			kept := map[string]string{}

			for _, who := range []string{"alice", "bob"} {
				p := filepath.Join(homes, who, "notes.txt")
				if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
					t.Fatal(err)
				}

				if err := os.WriteFile(p, []byte(who+"'s"), 0o600); err != nil {
					t.Fatal(err)
				}

				kept[p] = who + "'s"
			}

			mgr := &removing{fakeManager: fakeManager{d: paths.Default()}}
			standInService(t, mgr)

			out, errOut, code := capture(t, args...)
			if code != ExitError || !strings.Contains(errOut, "alice") || mgr.removals != 0 {
				t.Errorf("conflux %s of a folder of homes exited %d and removed the boot service %d times, want %d "+
					"naming alice/, nothing removed:\n%s%s", strings.Join(args, " "), code, mgr.removals, ExitError,
					out, errOut)
			}

			for p, was := range kept {
				if b, err := os.ReadFile(p); err != nil || string(b) != was {
					t.Errorf("conflux %s of a folder of homes left %s holding %q (%v), want %q", strings.Join(args, " "),
						p, b, err, was)
				}
			}
		})
	}
}

// TestUninstallLeavesAVolumesTop: a CONFLUX_DIR at the top of a volume is no root conflux empties, so
// uninstall refuses it before it acts, exit 1, the boot service not removed, saying what paths says it
// is. The folder a SUBST letter stands for, which need be no shared or system directory, paths refuses as
// the top of its volume (ErrTopRoot), and uninstall says that, not that it is shared; a volume's own root,
// / or C:\, paths refuses as a directory others keep what is theirs in, and uninstall says that, not
// that it is a volume's top.
func TestUninstallLeavesAVolumesTop(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	// Nothing is removed whatever the judging says: the question is never answered yes.
	defer func(was func(paths.Dirs, error, bool) bool) { confirm = was }(confirm)
	confirm = func(paths.Dirs, error, bool) bool { return false }

	const (
		topSaid    = "It is the top of its volume"
		sharedSaid = "It is a shared or system directory"
	)

	t.Run("a SUBST letter's folder", func(t *testing.T) {
		d := configured(t)

		// What paths' JudgeWays says of the top a SUBST letter gives a folder, which only Windows has.
		defer func(was func(paths.Dirs) error) { judgeWays = was }(judgeWays)
		judgeWays = func(paths.Dirs) error {
			return fmt.Errorf("Z:\\ is the top of its volume, so conflux will not use it as a root: %w", paths.ErrTopRoot)
		}

		mgr := &removing{fakeManager: fakeManager{d: d}}
		standInService(t, mgr)

		out, errOut, code := capture(t, "uninstall")
		if code != ExitError || !strings.Contains(errOut, topSaid) || strings.Contains(errOut, sharedSaid) ||
			mgr.removals != 0 {
			t.Errorf("uninstall of a SUBST letter's top exited %d and removed the boot service %d times, want %d "+
				"saying it is the top of its volume, nothing removed:\n%s%s", code, mgr.removals, ExitError, out, errOut)
		}
	})

	t.Run("a volume's root", func(t *testing.T) {
		top := filepath.VolumeName(t.TempDir()) + string(filepath.Separator)
		t.Setenv("CONFLUX_DIR", top)

		mgr := &removing{fakeManager: fakeManager{d: paths.Default()}}
		standInService(t, mgr)

		out, errOut, code := capture(t, "uninstall")
		if code != ExitError || !strings.Contains(errOut, sharedSaid) || strings.Contains(errOut, topSaid) ||
			mgr.removals != 0 {
			t.Errorf("uninstall of a CONFLUX_DIR of %s exited %d and removed the boot service %d times, want %d "+
				"saying it is a shared or system directory, nothing removed:\n%s%s", top, code, mgr.removals,
				ExitError, out, errOut)
		}
	})
}
