package cli

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/ghrelease/ghreleasetest"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/pathstest"
	"github.com/veil-net/conflux/internal/privcheck"
	"github.com/veil-net/conflux/internal/service"
	"github.com/veil-net/conflux/internal/update"
	"github.com/veil-net/conflux/internal/version"
)

// serveRelease stands in for conflux's `latest` release, holding body as this platform's
// binary, and points `conflux update` at it and at exe as the file to replace.
func serveRelease(t *testing.T, body []byte, exe string) *ghreleasetest.Release {
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

	return f
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

	rootOnLinux(t)

	exe := olderConflux(t)

	newer := []byte("#!/bin/sh\necho 'conflux 9.9.9 (0aea0f77bb77) " + runtime.GOOS + "/" + runtime.GOARCH + "'\n")
	serveRelease(t, newer, exe)

	out, errOut, code := capture(t, "update")
	if code != ExitOK || !strings.Contains(out, "Updated "+exe+": conflux 9.9.9") {
		t.Fatalf("update exited %d and printed:\n%s%s", code, out, errOut)
	}

	if got, _ := os.ReadFile(exe); string(got) != string(newer) {
		t.Errorf("the executable holds %q after the update", got)
	}

	if entries, _ := os.ReadDir(filepath.Dir(exe)); len(entries) != 1 {
		t.Errorf("the update left %d files where there was one", len(entries))
	}
}

// olderScript is a conflux older than any release, a shell script answering `version` as the real
// one does.
const olderScript = "#!/bin/sh\necho conflux 1.0.0 old\n"

// olderConflux puts olderScript in a directory of its own, as the file an update replaces, and
// returns its path.
func olderConflux(t *testing.T) string {
	t.Helper()

	exe := filepath.Join(t.TempDir(), "conflux")
	if err := os.WriteFile(exe, []byte(olderScript), 0o755); err != nil {
		t.Fatal(err)
	}

	return exe
}

// releaseAsking stands in for an update to rel, a release whose conflux, a shell script, answers
// `version` as the real one does and notes every other command it is asked, a line each, in the
// file asked; exe is the file the update replaces, an older conflux.
func releaseAsking(t *testing.T) (rel *ghreleasetest.Release, exe, asked string) {
	t.Helper()

	exe = olderConflux(t)
	asked = filepath.Join(t.TempDir(), "asked")
	rel = serveRelease(t, []byte("#!/bin/sh\ncase $1 in\n"+
		"version) echo 'conflux 9.9.9 (0aea0f77bb77) "+runtime.GOOS+"/"+runtime.GOARCH+"' ;;\n"+
		"*) echo \"$*\" >>'"+asked+"' ;;\nesac\n"), exe)

	return rel, exe, asked
}

// updatedConflux is a conflux an update replaced, exe, in a directory of the test's named x[1], which
// updateExecutable answers for the rest of the test, beside what an update leaves there: a download
// that never went in place, and exe.old, the image an update moves aside on Windows. leftovers are
// those conflux removes as what an update left, and kept those it keeps: exe.old is an update's on
// Windows alone, and elsewhere a file of the operator's; and a download in x1, which the folder taken
// as a pattern, not by its name, would reach.
func updatedConflux(t *testing.T) (exe string, leftovers, kept []string) {
	t.Helper()

	parent := t.TempDir()
	exe = filepath.Join(parent, "x[1]", "conflux")
	leftovers = []string{filepath.Join(filepath.Dir(exe), ".conflux-update-123")}
	kept = []string{filepath.Join(parent, "x1", ".conflux-update-123")}

	if runtime.GOOS == "windows" {
		leftovers = append(leftovers, exe+".old")
	} else {
		kept = append(kept, exe+".old")
	}

	for _, p := range append(append([]string{exe}, leftovers...), kept...) {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(p, []byte("a conflux"), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	was := updateExecutable
	t.Cleanup(func() { updateExecutable = was })

	updateExecutable = func() (string, error) { return exe, nil }

	return exe, leftovers, kept
}

// standInService makes mgr what newService answers, for the rest of the test; and where the test has
// not pointed updateExecutable at a conflux of its own, points it at one in a directory of the test's,
// so that what tidy and uninstall remove beside the conflux an update replaced
// (removeUpdateLeftovers) is looked for there, never beside the test binary.
func standInService(t *testing.T, mgr service.Manager) {
	t.Helper()

	was := newService
	t.Cleanup(func() { newService = was })

	newService = func() service.Manager { return mgr }

	if reflect.ValueOf(updateExecutable).Pointer() == reflect.ValueOf(service.Executable).Pointer() {
		exe := filepath.Join(t.TempDir(), "conflux")

		wasExe := updateExecutable
		t.Cleanup(func() { updateExecutable = wasExe })

		updateExecutable = func() (string, error) { return exe, nil }
	}
}

// TestUpdateHandsAStoppedServiceToTheNewConflux: with the boot service installed and the
// anchor stopped, the conflux the update put in place registers the service itself -- its
// own copy, defined as it defines it -- and nothing starts. This one registers nothing.
func TestUpdateHandsAStoppedServiceToTheNewConflux(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in conflux is a shell script")
	}

	rootOnLinux(t)

	_, _, asked := releaseAsking(t)

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
// starts nothing -- on a machine with a configuration to start, as every machine update
// hands a service to has.
func TestRegisterStartsNothing(t *testing.T) {
	anchortest.Require(t) // it extracts the pair afresh

	rootOnLinux(t)

	d := pathstest.Dirs(t)

	if err := config.Save(d, &config.Config{Mode: config.ModeProxy, Proxies: []string{"8080=127.0.0.1:3000"}, Taints: []string{"t"}}); err != nil {
		t.Fatal(err)
	}

	mgr := &fakeManager{restartErr: errStartsNothing}
	standInService(t, mgr)

	if _, errOut, code := capture(t, "register"); code != ExitOK {
		t.Fatalf("register exited %d: %s", code, errOut)
	}

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

	rootOnLinux(t)

	exe := olderConflux(t)
	serveRelease(t, []byte("#!/bin/sh\nexit 3\n"), exe)

	_, errOut, code := capture(t, "update")
	if code != ExitError || !strings.Contains(errOut, "does not run on this machine") {
		t.Errorf("update exited %d: %s", code, errOut)
	}

	if got, _ := os.ReadFile(exe); string(got) != olderScript {
		t.Error("a binary that does not run replaced the executable")
	}

	if entries, _ := os.ReadDir(filepath.Dir(exe)); len(entries) != 1 {
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

// TestAnInterruptedUpdateLetsTheNewConfluxFinish: Ctrl+C, or a SIGTERM to update alone, while the conflux
// an update put in place hands the service over -- its start or its register, which may have stopped the
// service -- ends update's ctx. The child is sent SIGTERM, which it takes as its own Ctrl+C, and waited
// for, so that its own finish starts again what it stopped, and update ends with its code; one that does
// not end is killed once childFinish has passed.
func TestAnInterruptedUpdateLetsTheNewConfluxFinish(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in conflux is a shell script")
	}

	was := childFinish
	t.Cleanup(func() { childFinish = was })

	childFinish = time.Second

	for _, tc := range []struct {
		name, trap string
		want       int
		finishes   bool
	}{
		{"finishing", `trap 'sleep 0.3; echo > "$0.finished"; exit 3' TERM`, 3, true},
		{"never ending", `trap '' TERM`, -1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			child := filepath.Join(t.TempDir(), "conflux")
			if err := os.WriteFile(child, []byte("#!/bin/sh\n"+tc.trap+"\necho > \"$0.started\"\n"+
				"while :; do sleep 0.05; done\n"), 0o700); err != nil {
				t.Fatal(err)
			}

			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			go func() {
				for deadline := time.Now().Add(childDeadline); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
					if _, err := os.Stat(child + ".started"); err == nil {
						break
					}
				}

				cancel()
			}()

			code := runChild(ctx, child, "start")

			if _, err := os.Stat(child + ".finished"); code != tc.want || (err == nil) != tc.finishes {
				t.Errorf("the child, its update interrupted, ended %d, finishing %v (%v); want %d, finishing %v",
					code, err == nil, err, tc.want, tc.finishes)
			}
		})
	}
}
