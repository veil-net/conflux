package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/service"
	"github.com/veil-net/conflux/internal/ui"
	"github.com/veil-net/conflux/internal/update"
	"github.com/veil-net/conflux/internal/version"
)

// serveRelease stands in for conflux's two releases, `latest` and the pre-release `dev-latest`,
// each holding body as this platform's binary, and points `conflux update` at them, at exe as
// the file to replace, and on Unix at a link of the test's own as the one it makes for sudo
// (pointSudoLink). It returns what an update asked it for, in order: the tag of each release it
// read, and "download" for each binary it fetched.
func serveRelease(t *testing.T, body []byte, exe string) *[]string {
	t.Helper()

	sum := sha256.Sum256(body)

	var (
		mu    sync.Mutex
		asked []string
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/repos/veil-net/conflux/releases/tags/{tag}", func(w http.ResponseWriter, r *http.Request) {
		tag := r.PathValue("tag")

		mu.Lock()
		asked = append(asked, tag)
		mu.Unlock()

		if tag != "latest" && tag != "dev-latest" {
			w.WriteHeader(http.StatusNotFound)

			return
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"name":             tag + " (9.9.9)",
			"target_commitish": "0aea0f77bb77f8bbaa23c5055d9fe245d3a9bee2",
			"assets": []map[string]any{{
				"id": 7, "name": update.AssetName(runtime.GOOS, runtime.GOARCH), "size": len(body),
				"state": "uploaded", "digest": "sha256:" + hex.EncodeToString(sum[:]),
			}},
		})
	})
	mux.HandleFunc("/repos/veil-net/conflux/releases/assets/7", func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		asked = append(asked, "download")
		mu.Unlock()

		_, _ = w.Write(body)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	t.Setenv(config.InsecureAPIEnv, "1")
	t.Cleanup(paths.UseRoot(t.TempDir()))

	was, wasExe := updateFrom, updateExecutable
	t.Cleanup(func() { updateFrom, updateExecutable = was, wasExe })

	updateFrom = update.Source{API: srv.URL}
	updateExecutable = func() string { return exe }

	pointSudoLink(t)

	return &asked
}

func TestUpdateSaysSoWhenThisIsTheRelease(t *testing.T) {
	exe := filepath.Join(t.TempDir(), "conflux")
	body := []byte("\x7fELF the release's own conflux")

	if err := os.WriteFile(exe, body, 0o755); err != nil {
		t.Fatal(err)
	}

	serveRelease(t, body, exe)

	out, _, code := capture(t, "update")
	if code != ExitOK || !strings.Contains(out, "newest release") {
		t.Errorf("update exited %d and printed:\n%s", code, out)
	}
}

// TestUpdateCheckChangesNothing: --check reports and touches nothing, root or not.
func TestUpdateCheckChangesNothing(t *testing.T) {
	asRoot(t, false)

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
	asRoot(t, false)

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

	asRoot(t, true)

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

// TestUpdateRefusesABinaryThatDoesNotRun: the right bytes, by digest, that are still no
// conflux this machine can run replace nothing.
func TestUpdateRefusesABinaryThatDoesNotRun(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in conflux is a shell script")
	}

	asRoot(t, true)

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

// TestAPlainUpdateTakesTheRelease: conflux update replaces the installed conflux with the newest
// release, `latest`, whatever is installed or running -- here a dev build, as its `version` says,
// run by a dev build -- and asks nothing first, at a terminal as off one.
func TestAPlainUpdateTakesTheRelease(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in conflux is a shell script")
	}

	asRoot(t, true)
	keepChannel(t)
	answer(t, "") // a terminal nothing is typed at, which would answer a question no

	version.Channel = "dev"

	exe := filepath.Join(t.TempDir(), "conflux")
	says := "conflux 1.0.0 (0aea0f77bb77) " + runtime.GOOS + "/" + runtime.GOARCH
	script := "#!/bin/sh\necho '" + says + "'\necho \"dev build: anchor's dev-latest, pinned to the dev tree\"\n"

	if err := os.WriteFile(exe, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	newer := []byte("#!/bin/sh\necho 'conflux 9.9.9 (0aea0f77bb77) " + runtime.GOOS + "/" + runtime.GOARCH + "'\n")
	asked := serveRelease(t, newer, exe)

	out, errOut, code := capture(t, "update", "--check")
	if code != ExitOK || !slices.Equal(*asked, []string{"latest"}) ||
		!strings.Contains(out, exe+" is "+says+".\nThe newest release is latest (9.9.9), built from 0aea0f77bb77.") {
		t.Errorf("update --check of an installed dev build, run by one, exited %d, asking for %q:\n%s%s", code, *asked, out, errOut)
	}

	*asked = nil

	out, errOut, code = capture(t, "update")
	if code != ExitOK || !slices.Equal(*asked, []string{"latest", "download"}) || strings.Contains(out, "[y/N]") ||
		!strings.Contains(out, "Updated "+exe+": conflux 9.9.9") {
		t.Errorf("update of an installed dev build, run by one, exited %d, asking for %q:\n%s%s", code, *asked, out, errOut)
	}

	if got, _ := os.ReadFile(exe); string(got) != string(newer) {
		t.Errorf("the executable holds %q after the update", got)
	}
}

// TestADevUpdateIsRefusedOffATerminal: conflux update --dev asks before it installs a dev build,
// and where there is no terminal to ask at it refuses, as up refuses an IPv4 nobody can give,
// whatever stdin holds: nothing is downloaded and nothing changes. No flag gets past it.
func TestADevUpdateIsRefusedOffATerminal(t *testing.T) {
	asRoot(t, true)

	was := ui.In
	ui.In = strings.NewReader("y\n")

	t.Cleanup(func() { ui.In = was })

	dir := t.TempDir()
	exe := filepath.Join(dir, "conflux")
	old := []byte("\x7fELF an older conflux")

	if err := os.WriteFile(exe, old, 0o755); err != nil {
		t.Fatal(err)
	}

	asked := serveRelease(t, []byte("\x7fELF the newest dev build"), exe)

	out, errOut, code := capture(t, "update", "--dev")
	if code != ExitError || !slices.Equal(*asked, []string{"dev-latest"}) || strings.Contains(out, "[y/N]") ||
		!strings.Contains(errOut, "update --dev asks before it installs a dev build, and there is no terminal to ask at") {
		t.Errorf("update --dev off a terminal exited %d, asking for %q:\n%s%s", code, *asked, out, errOut)
	}

	if got, _ := os.ReadFile(exe); string(got) != string(old) {
		t.Error("update --dev off a terminal changed the executable")
	}

	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("update --dev off a terminal left %d files where there was one", len(entries))
	}
}

// TestADevUpdateAsksFirst: at a terminal, conflux update --dev says what a dev build is -- its
// anchor pinned to the dev tree, where a credential from the production tree does not work --
// and asks before it downloads anything. y or yes takes the newest dev build, `dev-latest`; any
// other answer, nothing typed and the end of input among them, changes nothing, said in a line,
// and exits 2, as a declined observe or uninstall does. Not root, it is refused for privilege
// before it asks, so the command typed again under sudo asks once.
func TestADevUpdateAsksFirst(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in conflux is a shell script")
	}

	old := []byte("#!/bin/sh\necho conflux 1.0.0 old\n")
	newer := []byte("#!/bin/sh\necho 'conflux 9.9.9 (0aea0f77bb77) " + runtime.GOOS + "/" + runtime.GOARCH + "'\n")

	installed := func(t *testing.T) (dir, exe string) {
		t.Helper()

		dir = t.TempDir()
		exe = filepath.Join(dir, "conflux")

		if err := os.WriteFile(exe, old, 0o755); err != nil {
			t.Fatal(err)
		}

		return dir, exe
	}

	for name, c := range map[string]struct {
		typed string
		takes bool
	}{
		"y": {"y\n", true}, "yes": {"YES\n", true}, "n": {"n\n", false}, "nothing typed": {"\n", false},
		"the end of input": {"", false},
	} {
		t.Run(name, func(t *testing.T) {
			asRoot(t, true)
			answer(t, c.typed)

			dir, exe := installed(t)
			asked := serveRelease(t, newer, exe)

			out, errOut, code := capture(t, "update", "--dev")

			for _, want := range []string{
				"The newest dev build is dev-latest (9.9.9), built from 0aea0f77bb77.",
				"pinned to the dev tree", "production tree", "Install the dev build? [y/N]",
			} {
				if !strings.Contains(out, want) {
					t.Errorf("update --dev should say %q before it asks; it said:\n%s", want, out)
				}
			}

			got, _ := os.ReadFile(exe)

			if c.takes {
				if code != ExitOK || !slices.Equal(*asked, []string{"dev-latest", "download"}) || string(got) != string(newer) ||
					!strings.Contains(out, "Updated "+exe+": conflux 9.9.9") {
					t.Errorf("update --dev answered %q exited %d, asking for %q, the executable holding %q:\n%s%s",
						c.typed, code, *asked, got, out, errOut)
				}

				return
			}

			if code != ExitUsage || !slices.Equal(*asked, []string{"dev-latest"}) || string(got) != string(old) ||
				!strings.Contains(errOut, "nothing changed") {
				t.Errorf("update --dev answered %q exited %d, asking for %q, the executable holding %q:\n%s%s",
					c.typed, code, *asked, got, out, errOut)
			}

			if entries, _ := os.ReadDir(dir); len(entries) != 1 {
				t.Errorf("update --dev answered %q left %d files where there was one", c.typed, len(entries))
			}
		})
	}

	t.Run("not root", func(t *testing.T) {
		asRoot(t, false)
		answer(t, "y\n")

		_, exe := installed(t)
		asked := serveRelease(t, newer, exe)

		out, errOut, code := capture(t, "update", "--dev")
		if code != ExitDenied || strings.Contains(out, "[y/N]") || slices.Contains(*asked, "download") ||
			!strings.Contains(errOut, "conflux update --dev") {
			t.Errorf("update --dev, not root, exited %d, asking for %q:\n%s%s", code, *asked, out, errOut)
		}
	})
}

// TestADevCheckAsksNothing: conflux update --dev --check names the newest dev build, and the
// command that installs it, and changes nothing, so it asks nothing, at a terminal too, and needs
// no root. What is installed is said: nothing, then a file that does not run.
func TestADevCheckAsksNothing(t *testing.T) {
	asRoot(t, false)
	answer(t, "y\n")

	dir := t.TempDir()
	exe := filepath.Join(dir, "conflux")
	asked := serveRelease(t, []byte("\x7fELF the newest dev build"), exe)
	notConflux := []byte("\x7fELF no conflux that runs")

	for _, installed := range []string{"Nothing is installed at " + exe + ".", exe + " does not run here"} {
		*asked = nil

		out, errOut, code := capture(t, "update", "--dev", "--check")
		if code != ExitOK || !slices.Equal(*asked, []string{"dev-latest"}) || strings.Contains(out, "[y/N]") ||
			!strings.Contains(out, installed) ||
			!strings.Contains(out, "The newest dev build is dev-latest (9.9.9), built from 0aea0f77bb77.") ||
			!strings.Contains(out, "conflux update --dev") {
			t.Errorf("update --dev --check exited %d, asking for %q:\n%s%s", code, *asked, out, errOut)
		}

		if err := os.WriteFile(exe, notConflux, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	if got, _ := os.ReadFile(exe); string(got) != string(notConflux) {
		t.Error("update --dev --check changed the executable")
	}

	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("update --dev --check left %d files where there was one", len(entries))
	}
}

// answer makes this test's stdin a terminal, as update asks whether it is one (updateAtTerminal),
// at which typed is what is typed.
func answer(t *testing.T, typed string) {
	t.Helper()

	wasIn, wasTerminal := ui.In, updateAtTerminal
	ui.In, updateAtTerminal = strings.NewReader(typed), func() bool { return true }

	t.Cleanup(func() { ui.In, updateAtTerminal = wasIn, wasTerminal })
}

// keepChannel puts version.Channel back as it was when the test ends.
func keepChannel(t *testing.T) {
	t.Helper()

	was := version.Channel

	t.Cleanup(func() { version.Channel = was })
}

// TestUpdateWritesTheInstalledConflux: an update replaces the conflux the installers put in
// place, wherever the conflux running it was started from, and puts one there when there is
// none yet.
func TestUpdateWritesTheInstalledConflux(t *testing.T) {
	if got := updateExecutable(); got != paths.InstalledExecutable() {
		t.Errorf("update replaces %q, not the installed %s", got, paths.InstalledExecutable())
	}

	if runtime.GOOS == "windows" {
		t.Skip("the stand-in conflux is a shell script")
	}

	asRoot(t, true)

	exe := filepath.Join(t.TempDir(), "bin", "conflux")
	newer := []byte("#!/bin/sh\necho 'conflux 9.9.9 (0aea0f77bb77) " + runtime.GOOS + "/" + runtime.GOARCH + "'\n")
	serveRelease(t, newer, exe)

	out, errOut, code := capture(t, "update")
	if code != ExitOK || !strings.Contains(out, "Updated "+exe+": conflux 9.9.9") {
		t.Fatalf("update with nothing installed exited %d and printed:\n%s%s", code, out, errOut)
	}

	if got, _ := os.ReadFile(exe); string(got) != string(newer) {
		t.Errorf("the installed conflux holds %q after the update", got)
	}
}

// TestSameFileIsWhatAPathNames: whether a path is the conflux running -- update's question of the
// installed file, uninstall's on Windows of the directory it removes -- is asked of what the path
// names, not how it is spelled: the file this test runs is this process, by a link to it as by its
// own name, and another file is not; its directory is its directory however spelled, and another
// directory is not.
func TestSameFileIsWhatAPathNames(t *testing.T) {
	self, err := service.Executable()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	other := filepath.Join(dir, "conflux")

	if err := os.WriteFile(other, []byte("another conflux"), 0o755); err != nil {
		t.Fatal(err)
	}

	if !isThis(self) || isThis(other) {
		t.Errorf("isThis(%s) = %v, isThis(%s) = %v; want true, then false", self, isThis(self), other, isThis(other))
	}

	// Where this account may make a link: on Windows, an elevated one or developer mode.
	if link := filepath.Join(dir, "link"); os.Symlink(self, link) == nil && !isThis(link) {
		t.Errorf("isThis(%s), a link to this process's file, is false", link)
	}

	spellings := []string{filepath.Dir(self) + string(filepath.Separator) + "."}
	if runtime.GOOS == "windows" {
		spellings = append(spellings, strings.ToUpper(filepath.Dir(self)))
	}

	for _, s := range spellings {
		if !sameFile(filepath.Dir(self), s) {
			t.Errorf("sameFile(%s, %s) is false", filepath.Dir(self), s)
		}
	}

	if sameFile(filepath.Dir(self), dir) {
		t.Errorf("sameFile(%s, %s), two directories, is true", filepath.Dir(self), dir)
	}
}
