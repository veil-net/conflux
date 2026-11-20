package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/ghrelease/ghreleasetest"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/privcheck"
	"github.com/veil-net/conflux/internal/service"
	"github.com/veil-net/conflux/internal/update"
	"github.com/veil-net/conflux/internal/version"
)

// serveRelease stands in for conflux's `latest` release, holding body as this platform's
// binary, and points `conflux update` at it and at exe as the file to replace.
func serveRelease(t *testing.T, body []byte, exe string) {
	t.Helper()

	f := &ghreleasetest.Release{
		Repo:   update.DefaultRepo,
		Name:   "latest (9.9.9)",
		Commit: "0aea0f77bb77f8bbaa23c5055d9fe245d3a9bee2",
		Files:  map[string][]byte{update.AssetName(runtime.GOOS, runtime.GOARCH): body},
	}

	api := f.Serve(t)

	t.Setenv("CONFLUX_DIR", t.TempDir())

	was, wasExe := updateFrom, updateExecutable
	t.Cleanup(func() { updateFrom, updateExecutable = was, wasExe })

	updateFrom = update.Source{API: api}
	updateExecutable = func() (string, error) { return exe, nil }
}

func TestUpdateTakesNoArguments(t *testing.T) {
	_, errOut, code := capture(t, "update", "1.2.0")
	if code != ExitUsage || !strings.Contains(errOut, "takes no arguments") {
		t.Errorf("update 1.2.0 exited %d: %s", code, errOut)
	}
}

func TestUpdateSaysSoWhenThisIsTheRelease(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "conflux")
	body := []byte("\x7fELF the release's own conflux")

	if err := os.WriteFile(exe, body, 0o755); err != nil {
		t.Fatal(err)
	}

	serveRelease(t, body, exe)

	out, _, code := capture(t, "update")
	if code != ExitOK || !strings.Contains(out, "latest release") {
		t.Errorf("update exited %d and printed:\n%s", code, out)
	}
}

// TestUpdateCheckChangesNothing: --check reports and touches nothing, root or not.
func TestUpdateCheckChangesNothing(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return false }

	dir := t.TempDir()
	exe := filepath.Join(dir, "conflux")
	old := []byte("\x7fELF an older conflux")

	if err := os.WriteFile(exe, old, 0o755); err != nil {
		t.Fatal(err)
	}

	serveRelease(t, []byte("\x7fELF a newer conflux"), exe)

	out, _, code := capture(t, "update", "--check")
	if code != ExitOK || !strings.Contains(out, "latest (9.9.9)") || !strings.Contains(out, "0aea0f77bb77") {
		t.Errorf("update --check exited %d and printed:\n%s", code, out)
	}

	if got, _ := os.ReadFile(exe); string(got) != string(old) {
		t.Error("update --check changed the executable")
	}

	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("update --check left %d files where there was one", len(entries))
	}
}

func TestUpdateNeedsRoot(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return false }

	exe := filepath.Join(t.TempDir(), "conflux")
	if err := os.WriteFile(exe, []byte("\x7fELF an older conflux"), 0o755); err != nil {
		t.Fatal(err)
	}

	serveRelease(t, []byte("\x7fELF a newer conflux"), exe)

	if _, _, code := capture(t, "update"); code != ExitDenied {
		t.Errorf("update without root exited %d, want %d", code, ExitDenied)
	}
}

// TestUpdateReplacesTheExecutable: the whole path, with a stand-in conflux that answers
// `version` the way the real one does. On a machine with no boot service, it ends there.
func TestUpdateReplacesTheExecutable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in conflux is a shell script")
	}

	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	dir := t.TempDir()
	exe := filepath.Join(dir, "conflux")

	if err := os.WriteFile(exe, []byte("#!/bin/sh\necho conflux 1.0.0 old\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	newer := []byte("#!/bin/sh\necho 'conflux 9.9.9 (0aea0f77bb77) " + runtime.GOOS + "/" + runtime.GOARCH + "'\n")
	serveRelease(t, newer, exe)

	out, errOut, code := capture(t, "update")
	if code != ExitOK || !strings.Contains(out, "Updated "+exe+": conflux 9.9.9") {
		t.Fatalf("update exited %d and printed:\n%s%s", code, out, errOut)
	}

	if got, _ := os.ReadFile(exe); string(got) != string(newer) {
		t.Errorf("the executable holds %q after the update", got)
	}

	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("the update left %d files where there was one", len(entries))
	}
}

// standInService makes the boot manager install and update use mgr.
func standInService(t *testing.T, mgr service.Manager) {
	t.Helper()

	was := newService
	t.Cleanup(func() { newService = was })

	newService = func() service.Manager { return mgr }
}

// TestUpdateHandsAStoppedServiceToTheNewConflux: with the boot service installed and the
// anchor stopped, the conflux the update put in place registers the service itself -- its
// own copy, defined as it defines it -- and nothing starts. This one registers nothing.
func TestUpdateHandsAStoppedServiceToTheNewConflux(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in conflux is a shell script")
	}

	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	exe := filepath.Join(t.TempDir(), "conflux")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\necho conflux 1.0.0 old\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	asked := filepath.Join(t.TempDir(), "asked")
	newer := []byte("#!/bin/sh\ncase $1 in\n" +
		"version) echo 'conflux 9.9.9 (0aea0f77bb77) " + runtime.GOOS + "/" + runtime.GOARCH + "' ;;\n" +
		"*) echo \"$*\" >>'" + asked + "' ;;\nesac\n")
	serveRelease(t, newer, exe)

	mgr := &fakeManager{}
	standInService(t, mgr)

	out, errOut, code := capture(t, "update")
	if code != ExitOK || !strings.Contains(out, "not running") {
		t.Fatalf("update exited %d and printed:\n%s%s", code, out, errOut)
	}

	if got, _ := os.ReadFile(asked); string(got) != "register\n" {
		t.Errorf("the new conflux was asked %q, want its register alone", got)
	}

	if len(mgr.installs) != 0 || mgr.restarts != 0 {
		t.Errorf("this conflux registered %q and restarted %d times; the new one registers, and nothing starts",
			mgr.installs, mgr.restarts)
	}
}

// TestRegisterStartsNothing: the step update hands a stopped service to, in the conflux it
// put in place, places that conflux's copy and registers the service as it defines it, and
// starts nothing.
func TestRegisterStartsNothing(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	t.Setenv("CONFLUX_DIR", t.TempDir())

	mgr := &fakeManager{}
	standInService(t, mgr)

	if _, errOut, code := capture(t, "register"); code != ExitOK {
		t.Fatalf("register exited %d: %s", code, errOut)
	}

	d := paths.Default()

	want := []string{d.ServiceExecutable(), "serve", "--dir", paths.Root()}
	if len(mgr.installs) != 1 || !slices.Equal(mgr.installs[0], want) {
		t.Errorf("register registered %q, want %q once", mgr.installs, want)
	}

	if mgr.restarts != 0 {
		t.Errorf("register started the service %d times", mgr.restarts)
	}

	if _, err := os.Stat(d.ServiceExecutable()); err != nil {
		t.Errorf("register placed no copy for the service: %v", err)
	}

	if _, errOut, code := capture(t, "register", "now"); code != ExitUsage || !strings.Contains(errOut, "no arguments") {
		t.Errorf("register now exited %d: %s", code, errOut)
	}
}

// TestUpdateRefusesABinaryThatDoesNotRun: the right bytes, by digest, that are still no
// conflux this machine can run replace nothing.
func TestUpdateRefusesABinaryThatDoesNotRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in conflux is a shell script")
	}

	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	dir := t.TempDir()
	exe := filepath.Join(dir, "conflux")
	old := []byte("#!/bin/sh\necho conflux 1.0.0 old\n")

	if err := os.WriteFile(exe, old, 0o755); err != nil {
		t.Fatal(err)
	}

	serveRelease(t, []byte("#!/bin/sh\nexit 3\n"), exe)

	_, errOut, code := capture(t, "update")
	if code != ExitError || !strings.Contains(errOut, "does not run on this machine") {
		t.Errorf("update exited %d: %s", code, errOut)
	}

	if got, _ := os.ReadFile(exe); string(got) != string(old) {
		t.Error("a binary that does not run replaced the executable")
	}

	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("the refused update left %d files where there was one", len(entries))
	}
}

// TestADevBuildAsksBeforeLeaving: a dev build's anchor is pinned to the dev tree, and the
// release's to the production one, so an update from a dev build is refused until it is asked
// for with --yes, and changes nothing until then; --check says why, and changes nothing either.
func TestADevBuildAsksBeforeLeaving(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return false }

	defer func(was string) { version.Channel = was }(version.Channel)
	version.Channel = "dev"

	exe := filepath.Join(t.TempDir(), "conflux")
	old := []byte("\x7fELF a dev build")

	if err := os.WriteFile(exe, old, 0o755); err != nil {
		t.Fatal(err)
	}

	serveRelease(t, []byte("\x7fELF the release"), exe)

	_, errOut, code := capture(t, "update")
	if code != ExitUsage || !strings.Contains(errOut, "dev build") || !strings.Contains(errOut, "--yes") {
		t.Errorf("update on a dev build exited %d and said:\n%s", code, errOut)
	}

	out, _, code := capture(t, "update", "--check")
	if code != ExitOK || !strings.Contains(out, "dev build") {
		t.Errorf("update --check on a dev build exited %d and printed:\n%s", code, out)
	}

	if got, _ := os.ReadFile(exe); string(got) != string(old) {
		t.Error("a refused update changed the executable")
	}

	// Asked for by name, it goes on to what any update needs: root, here refused.
	if _, _, code := capture(t, "update", "--yes"); code != ExitDenied {
		t.Errorf("update --yes on a dev build exited %d, want %d: root is what it needs next", code, ExitDenied)
	}
}
