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

	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/libexec"
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

// TestUninstallLeavesNoTrace: a fresh install and its uninstall leave the tree exactly as it was. The
// CONFLUX_DIR is either a folder conflux makes, on a way it makes, which uninstall removes with the
// way; or a folder of the user's, holding a bin/, a .ssh/ and a file, which conflux never changes: its
// root is .conflux inside it. Either way everything conflux made goes -- its root, with what the user
// put in it and in its run/, bin/ and logs/, a killed ephemeral run's root, the temporary copy of
// anchorctl a killed reader left -- and nothing else.
func TestUninstallLeavesNoTrace(t *testing.T) {
	anchortest.Require(t) // the run extracts the pair

	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	for _, users := range []bool{false, true} {
		name := "conflux makes the CONFLUX_DIR"
		if users {
			name = "the CONFLUX_DIR is the user's"
		}

		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			dir := filepath.Join(base, "made", "here")

			if users {
				dir = filepath.Join(base, "home")

				for p, mode := range map[string]os.FileMode{
					filepath.Join(dir, "bin", "backup.sh"): 0o755,
					filepath.Join(dir, ".ssh", "id"):       0o600,
					filepath.Join(dir, "notes.txt"):        0o644,
				} {
					if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
						t.Fatal(err)
					}

					if err := os.WriteFile(p, []byte("the user's"), mode); err != nil {
						t.Fatal(err)
					}
				}
			}

			// Where a reader keeps its temporary anchorctl, which a killed one leaves.
			tmp := filepath.Join(base, "tmp")
			if err := os.Mkdir(tmp, 0o700); err != nil {
				t.Fatal(err)
			}

			for _, name := range []string{"TMPDIR", "TMP", "TEMP"} {
				t.Setenv(name, tmp)
			}

			before := snapshot(t, base)

			t.Setenv("CONFLUX_DIR", dir)

			d := paths.Default()
			mgr := &fakeManager{d: d}
			standInService(t, mgr)
			recordAccounts(t)

			defer func(was func(paths.Dirs, time.Duration)) { reap = was }(reap)
			reap = func(paths.Dirs, time.Duration) {}

			if out, errOut, code := capture(t, "install"); code != ExitOK {
				t.Fatalf("install exited %d:\n%s%s", code, out, errOut)
			}

			// What a run leaves: the configuration, the identity, the state, the extracted pair, the run
			// directory's marker, and a killed ephemeral run's root; and what the user put in conflux's.
			if err := config.Save(d, &config.Config{Mode: config.ModeProxy, Proxies: []string{"8080=127.0.0.1:3000"},
				Taints: []string{"t"}}); err != nil {
				t.Fatal(err)
			}

			if err := config.SaveManifest(d, config.Envelope("bWFuaWZlc3Q=")); err != nil {
				t.Fatal(err)
			}

			if _, err := libexec.Extract(d); err != nil {
				t.Fatal(err)
			}

			if err := daemon.MarkReady(d, "anchorid"); err != nil {
				t.Fatal(err)
			}

			planted := []string{filepath.Join(d.State, "mine.txt"), filepath.Join(d.Run, "mine.txt"),
				filepath.Join(d.Libexec(), "mine.txt"), filepath.Join(paths.EphemeralCandidates()[0], "serve.lock"),
				filepath.Join(tmp, "conflux-usage-123", binName("anchorctl"))}
			if d.Log != "" {
				planted = append(planted, filepath.Join(d.Log, "mine.txt"))
			}

			for _, p := range planted {
				if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
					t.Fatal(err)
				}

				if err := os.WriteFile(p, []byte("put there"), 0o600); err != nil {
					t.Fatal(err)
				}
			}

			if out, errOut, code := capture(t, "uninstall", "--yes"); code != ExitOK {
				t.Fatalf("uninstall exited %d:\n%s%s", code, out, errOut)
			}

			after := snapshot(t, base)

			for p, was := range before {
				if after[p] != was {
					t.Errorf("%s was %q before the install, and is %q after the uninstall", p, was, after[p])
				}
			}

			for p, is := range after {
				if _, ok := before[p]; !ok {
					t.Errorf("the uninstall left %s (%s)", p, is)
				}
			}
		})
	}
}

// snapshot is every path under base, by its path within it, with its mode, and what a file holds or
// where a link leads.
func snapshot(t *testing.T, base string) map[string]string {
	t.Helper()

	found := map[string]string{}

	if err := filepath.WalkDir(base, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		fi, err := e.Info()
		if err != nil {
			return err
		}

		was := fi.Mode().String()

		switch {
		case fi.Mode()&fs.ModeSymlink != 0:
			target, _ := os.Readlink(p)
			was += " -> " + target
		case fi.Mode().IsRegular():
			b, _ := os.ReadFile(p)
			was += " " + string(b)
		}

		rel, _ := filepath.Rel(base, p)
		found[rel] = was

		return nil
	}); err != nil {
		t.Fatal(err)
	}

	return found
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
	defer func(was func(string) error) { checkEphemeral = was }(checkEphemeral)
	checkEphemeral = func(string) error { return nil }

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

// TestUninstallStopsWhereARootsWayCannotBeWalked: a CONFLUX_DIR beneath a file has a way conflux cannot
// walk, which is not JudgeWays's refusal of a way another account may change -- nobody else need be able
// to change anything for it -- so uninstall says it stopped there, before it acted, exit 1, the boot
// service not removed, and not that another account may change the way; the file is left as it was.
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
		strings.Contains(errOut, "Once nobody else can change") {
		t.Errorf("uninstall of a CONFLUX_DIR beneath a file exited %d, want %d saying it stopped before it acted:\n%s%s",
			code, ExitError, out, errOut)
	}

	if b, err := os.ReadFile(file); err != nil || string(b) != "somebody's" || mgr.removals > 0 {
		t.Errorf("uninstall of a CONFLUX_DIR beneath a file removed the boot service %d times, and left the file %q, "+
			"%v", mgr.removals, b, err)
	}
}

// TestUninstallAsksNothingWithoutAnIdentity: where no identity is there, uninstall has nothing
// irreversible to ask about, in a CONFLUX_DIR as on the platform's roots: off a terminal and without
// --yes it removes the root, exit 0.
func TestUninstallAsksNothingWithoutAnIdentity(t *testing.T) {
	if ui.IsTerminal() {
		t.Skip("this test's stdin is a terminal")
	}

	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	d := configured(t)

	mgr := &removing{fakeManager: fakeManager{d: d}}
	standInService(t, mgr)
	recordAccounts(t)

	out, errOut, code := capture(t, "uninstall")
	if code != ExitOK || mgr.removals != 1 {
		t.Errorf("uninstall of a CONFLUX_DIR with no identity, off a terminal and without --yes, exited %d and "+
			"removed the boot service %d times, want %d and once:\n%s%s", code, mgr.removals, ExitOK, out, errOut)
	}

	if _, err := os.Lstat(d.State); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("uninstall left %s (Lstat: %v)", d.State, err)
	}
}

// TestUninstallSaysItRemovesTheCredentialInAChosenFolder: a CONFLUX_DIR's root holding an identity holds
// the one copy of this machine's credential, so uninstall, off a terminal and without --yes, refuses,
// exit 2, saying it would remove that root and everything in it, the credential among it, of which there
// is no other copy, with nothing removed.
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

	want := "removes " + d.State + " and everything in it, this machine's credential among it, and there is no " +
		"other copy of that"

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
