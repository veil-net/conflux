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
	"github.com/veil-net/conflux/internal/pathstest"
	"github.com/veil-net/conflux/internal/privcheck"
	"github.com/veil-net/conflux/internal/ui"
)

// TestUninstallLeavesNothingConfluxMade: uninstall removes everything conflux made, the identity,
// configuration and state included, and keeps nothing for a reinstall; and it removes what it finds
// there without following it. A link planted in a root -- to a directory outside it -- is removed as
// the link, and the directory it leads to, and what is in it, are untouched; a file planted there
// that another account owns is removed as itself. What an update left beside the conflux it
// replaced goes too, and that conflux stays, with whatever else is beside it: they are the
// operator's. What a dead supervisor left running is stopped first. A killed ephemeral run's root, in
// the runtime folder, is not touched. It says what it removed. (On Windows, with a junction: the same
// test.)
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

	plantLink(t, filepath.Join(d.Root, ".tmp-planted-link"), outside)
	plantLink(t, filepath.Join(d.Libexec(), "0123456789abcdef", "planted-link"), outside)
	plantForeign(t, filepath.Join(d.Root, ".tmp-planted-foreign"))

	mgr := &fakeManager{d: d}
	standInService(t, mgr)

	accounts := recordAccounts(t)

	// What uninstall stops: the anchord a dead supervisor left, by the root's pid record, which passes
	// the readers' check.
	var reaped []string

	defer func(was func(paths.Dirs, time.Duration)) { reap = was }(reap)
	reap = func(d paths.Dirs, _ time.Duration) { reaped = append(reaped, d.Root) }

	out, errOut, code := capture(t, "uninstall", "--yes")
	if code != ExitOK {
		t.Fatalf("uninstall exited %d, saying:\n%s%s", code, out, errOut)
	}

	if !slices.Equal(*accounts, []bool{true}) {
		t.Errorf("uninstall removed the accounts anchord ran as %v, want once, the ephemeral run's with them", *accounts)
	}

	if !slices.Equal(reaped, []string{d.Root}) {
		t.Errorf("uninstall reaped %q, want %s, once", reaped, d.Root)
	}

	if _, err := os.Lstat(filepath.Join(old.ephemeral, "serve.lock")); err != nil {
		t.Errorf("uninstall touched %s, a killed ephemeral run's root, which the system empties at boot: %v",
			old.ephemeral, err)
	}

	if _, err := os.Lstat(d.Root); !os.IsNotExist(err) {
		var left []string

		_ = filepath.WalkDir(d.Root, func(p string, _ fs.DirEntry, _ error) error {
			left = append(left, p)

			return nil
		})

		t.Errorf("uninstall left %s (Lstat: %v), holding:\n%s", d.Root, err, strings.Join(left, "\n"))
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

	for _, p := range append(old.leftovers, d.Root) {
		if !strings.Contains(out, "  "+p+"\n") {
			t.Errorf("uninstall did not say it removed %s:\n%s", p, out)
		}
	}
}

// TestUninstallLeavesNoTrace: a fresh install and its uninstall leave the tree exactly as it was. The
// installation's root is .conflux in the system's data folder, which holds other programs' files that
// conflux never changes. Everything conflux made goes -- its root, with what the user put in it and in its
// run/, bin/ and logs/, the temporary copy of anchorctl a killed reader left -- and nothing else.
func TestUninstallLeavesNoTrace(t *testing.T) {
	anchortest.Require(t) // the run extracts the pair

	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	base := t.TempDir()
	dir := filepath.Join(base, "lib")

	for p, mode := range map[string]os.FileMode{
		filepath.Join(dir, "dpkg", "status"): 0o644,
		filepath.Join(dir, "private", "key"): 0o600,
		filepath.Join(dir, "notes.txt"):      0o644,
	} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(p, []byte("another program's"), mode); err != nil {
			t.Fatal(err)
		}
	}

	// Where a reader keeps its temporary anchorctl, which a killed one leaves.
	tmp := pathstest.Temporary(t, filepath.Join(base, "tmp"))
	if err := os.Mkdir(tmp, 0o700); err != nil {
		t.Fatal(err)
	}

	before := snapshot(t, base)

	d := pathstest.RootedIn(t, dir)
	mgr := &fakeManager{d: d}
	standInService(t, mgr)
	recordAccounts(t)

	defer func(was func(paths.Dirs, time.Duration)) { reap = was }(reap)
	reap = func(paths.Dirs, time.Duration) {}

	if out, errOut, code := capture(t, "install"); code != ExitOK {
		t.Fatalf("install exited %d:\n%s%s", code, out, errOut)
	}

	// What a run leaves: the configuration, the identity, the state, the extracted pair and the run
	// directory's marker; and what the user put in conflux's.
	if err := config.Save(d, &config.Config{Mode: config.ModeProxy, Proxies: []string{"8080=127.0.0.1:3000"},
		Taints: []string{"t"}}); err != nil {
		t.Fatal(err)
	}

	if err := config.SaveManifest(d, config.Envelope("bWFuaWZlc3Q=")); err != nil {
		t.Fatal(err)
	}

	if _, err := libexec.Extract(t.Context(), d); err != nil {
		t.Fatal(err)
	}

	if err := daemon.MarkReady(d, "anchorid"); err != nil {
		t.Fatal(err)
	}

	planted := []string{filepath.Join(d.Root, "mine.txt"), filepath.Join(d.RunDir(), "mine.txt"),
		filepath.Join(d.Libexec(), "mine.txt"), filepath.Join(tmp, "conflux-usage-123", binName("anchorctl"))}
	if d.LogDir() != "" {
		planted = append(planted, filepath.Join(d.LogDir(), "mine.txt"))
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

// TestUninstallLeavesALiveRun: a live ephemeral run as root runs as the account uninstall removes, so
// while one is live uninstall refuses, exit 2, naming it, before anything is asked or removed, and again
// once the question is answered, for one started as it was asked; and one that starts once uninstall has
// begun -- here as the boot service is removed -- is left running, with its root and the account it runs
// as, and uninstall says so, exit 1, listing what it removed all the same.
func TestUninstallLeavesALiveRun(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	t.Run("live as uninstall begins", func(t *testing.T) {
		d := oldInstall(t).d
		e := ephemeralRoot(t)
		t.Cleanup(holdRoot(t, e))

		mgr := &removing{fakeManager: fakeManager{d: d}}
		standInService(t, mgr)

		out, errOut, code := capture(t, "uninstall", "--yes")
		if code != ExitUsage || !strings.Contains(errOut, e.Root) {
			t.Errorf("uninstall beside a live run exited %d, want %d naming %s:\n%s%s", code, ExitUsage, e.Root,
				out, errOut)
		}

		if _, err := os.Lstat(d.ConfigFile()); mgr.removals > 0 || err != nil {
			t.Errorf("uninstall beside a live run removed the boot service %d times, and %s (Lstat: %v)",
				mgr.removals, d.ConfigFile(), err)
		}
	})

	t.Run("live once asked", func(t *testing.T) {
		d := oldInstall(t).d
		e := ephemeralRoot(t)

		defer func(was func(paths.Dirs, error, bool) bool) { confirm = was }(confirm)
		confirm = func(paths.Dirs, error, bool) bool {
			t.Cleanup(holdRoot(t, e))

			return true
		}

		mgr := &removing{fakeManager: fakeManager{d: d}}
		standInService(t, mgr)

		out, errOut, code := capture(t, "uninstall", "--yes")
		if code != ExitUsage || !strings.Contains(errOut, e.Root) {
			t.Errorf("uninstall beside a run started as it asked exited %d, want %d naming %s:\n%s%s", code, ExitUsage,
				e.Root, out, errOut)
		}

		if _, err := os.Lstat(d.ConfigFile()); mgr.removals > 0 || err != nil {
			t.Errorf("uninstall beside a run started as it asked removed the boot service %d times, and %s (Lstat: %v)",
				mgr.removals, d.ConfigFile(), err)
		}
	})

	t.Run("started since", func(t *testing.T) {
		d := oldInstall(t).d
		e := ephemeralRoot(t)

		mgr := &removing{fakeManager: fakeManager{d: d}, then: func() { t.Cleanup(holdRoot(t, e)) }}
		standInService(t, mgr)

		accounts := recordAccounts(t)

		out, errOut, code := capture(t, "uninstall", "--yes")
		if code != ExitError || !strings.Contains(errOut, e.Root) || !strings.Contains(errOut, "left running") {
			t.Errorf("uninstall with a run started as it began exited %d, want %d naming %s, left running:\n%s%s",
				code, ExitError, e.Root, out, errOut)
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

// TestUninstallAsksNothingWithoutAnIdentity: where no identity is there, uninstall has nothing
// irreversible to ask about: off a terminal and without --yes it removes the root, exit 0.
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
		t.Errorf("uninstall with no identity, off a terminal and without --yes, exited %d and "+
			"removed the boot service %d times, want %d and once:\n%s%s", code, mgr.removals, ExitOK, out, errOut)
	}

	if _, err := os.Lstat(d.Root); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("uninstall left %s (Lstat: %v)", d.Root, err)
	}
}

// TestUninstallSaysItRemovesTheCredential: a root holding an identity holds the one copy of this
// machine's credential, so uninstall, off a terminal and without --yes, refuses, exit 2, saying it would
// delete it, of which there is no other copy, with nothing removed.
func TestUninstallSaysItRemovesTheCredential(t *testing.T) {
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

	const want = "deletes this machine's credential, and there is no other copy"

	out, errOut, code := capture(t, "uninstall")
	if code != ExitUsage || !strings.Contains(errOut, want) || !strings.Contains(errOut, "--yes") {
		t.Errorf("uninstall of a root holding an identity, off a terminal and without --yes, exited %d, want %d "+
			"saying it %s and naming --yes:\n%s%s", code, ExitUsage, want, out, errOut)
	}

	if _, err := os.Lstat(d.ManifestFile()); err != nil || mgr.removals > 0 {
		t.Errorf("uninstall, unconfirmed, removed the boot service %d times, and %s (Lstat: %v)", mgr.removals,
			d.ManifestFile(), err)
	}
}
