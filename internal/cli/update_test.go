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
	"github.com/veil-net/conflux/internal/update"
	"github.com/veil-net/conflux/internal/version"
)

// serveRelease stands in for conflux's two releases, `latest` and the pre-release `dev-latest`,
// each holding body as this platform's binary, and points `conflux update` at them, at exe as
// the file to replace, and at a link of the test's own as the one it makes for sudo. It returns
// the tags an update asked for, in order.
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
		_, _ = w.Write(body)
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	t.Setenv(config.InsecureAPIEnv, "1")
	t.Cleanup(paths.UseRoot(t.TempDir()))

	was, wasExe, wasLink := updateFrom, updateExecutable, updateLink
	t.Cleanup(func() { updateFrom, updateExecutable, updateLink = was, wasExe, wasLink })

	link := filepath.Join(t.TempDir(), "conflux")

	updateFrom = update.Source{API: srv.URL}
	updateExecutable = func() string { return exe }
	updateLink = func() string { return link }

	return &asked
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

// TestAnUpdateFollowsTheInstalledConfluxsChannel: an update replaces the installed conflux with
// the newest build of that conflux's channel -- `latest` for a release, `dev-latest` for a dev
// build, as its `version` says -- whichever channel the conflux running the update is on: a dev
// build's anchor is pinned to the dev tree and a release's to the production tree, and the
// credential the machine holds is valid in the installed one's alone. So nothing is asked
// first, and no flag crosses from one to the other.
func TestAnUpdateFollowsTheInstalledConfluxsChannel(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in conflux is a shell script")
	}

	asRoot(t, false)
	keepChannel(t)

	for _, dev := range []bool{false, true} {
		exe := filepath.Join(t.TempDir(), "conflux")
		says := "conflux 1.0.0 (0aea0f77bb77) " + runtime.GOOS + "/" + runtime.GOARCH
		script := "#!/bin/sh\necho '" + says + "'\n"
		want, running := "latest", "dev"

		if dev {
			script += "echo \"dev build: anchor's dev-latest, pinned to the dev tree\"\n"
			want, running = "dev-latest", ""
		}

		if err := os.WriteFile(exe, []byte(script), 0o755); err != nil {
			t.Fatal(err)
		}

		version.Channel = running
		asked := serveRelease(t, []byte("\x7fELF the newest build"), exe)

		out, errOut, code := capture(t, "update", "--check")
		if code != ExitOK || !slices.Equal(*asked, []string{want}) || !strings.Contains(out, exe+" is "+says) {
			t.Errorf("update --check of an installed dev build %v, run by channel %q, exited %d, reading %q:\n%s%s",
				dev, running, code, *asked, out, errOut)
		}

		// Nothing more to ask for: it goes on to what any update needs, root, here refused.
		if _, errOut, code := capture(t, "update"); code != ExitDenied {
			t.Errorf("update of an installed dev build %v exited %d, want %d:\n%s", dev, code, ExitDenied, errOut)
		}
	}

	if _, _, code := capture(t, "update", "--yes"); code != ExitUsage {
		t.Errorf("update --yes exited %d, want %d: no flag crosses channels", code, ExitUsage)
	}
}

// TestAnUpdateWithNoInstalledChannelFollowsThisBuild: with nothing installed, or an installed
// file that does not run and so cannot say what it is, the conflux running the update decides
// the channel, and says which it went by.
func TestAnUpdateWithNoInstalledChannelFollowsThisBuild(t *testing.T) {
	keepChannel(t)

	for channel, want := range map[string]string{"": "latest", "dev": "dev-latest"} {
		version.Channel = channel

		exe := filepath.Join(t.TempDir(), "conflux")
		asked := serveRelease(t, []byte("\x7fELF the newest build"), exe)

		out, _, code := capture(t, "update", "--check")
		if code != ExitOK || !slices.Equal(*asked, []string{want}) || !strings.Contains(out, "Nothing is installed at "+exe) {
			t.Errorf("update --check with nothing installed, on channel %q, exited %d, reading %q:\n%s", channel, code, *asked, out)
		}

		if err := os.WriteFile(exe, []byte("\x7fELF no conflux that runs"), 0o755); err != nil {
			t.Fatal(err)
		}

		*asked = nil

		out, _, code = capture(t, "update", "--check")
		if code != ExitOK || !slices.Equal(*asked, []string{want}) || !strings.Contains(out, exe+" does not run") {
			t.Errorf("update --check of an installed file that does not run, on channel %q, exited %d, reading %q:\n%s",
				channel, code, *asked, out)
		}
	}
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

// TestAFreshUpdateLinksItForSudo: on Unix an update that installs conflux where there was none
// makes the link install.sh makes for sudo, where the update's own PATH -- root's, under sudo --
// leaves the installed file's directory out; and, as install.sh does, makes none where that PATH
// holds it, and leaves a file of the link's name that is not that link alone, saying so.
func TestAFreshUpdateLinksItForSudo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows puts the directory on the machine's Path; TestUpdatePutsThePathEntry")
	}

	asRoot(t, true)

	newer := []byte("#!/bin/sh\necho 'conflux 9.9.9 (0aea0f77bb77) " + runtime.GOOS + "/" + runtime.GOARCH + "'\n")

	for _, c := range []struct {
		name    string
		onPath  bool
		foreign bool
	}{
		{name: "a PATH that leaves it out"},
		{name: "a PATH that holds it", onPath: true},
		{name: "a file at the link's name", foreign: true},
	} {
		exe := filepath.Join(t.TempDir(), "bin", "conflux")
		serveRelease(t, newer, exe)
		link := updateLink()

		t.Setenv("PATH", "/usr/bin:/bin")

		if c.onPath {
			t.Setenv("PATH", "/usr/bin:/bin:"+filepath.Dir(exe)+"/")
		}

		if c.foreign {
			if err := os.WriteFile(link, []byte("somebody else's"), 0o755); err != nil {
				t.Fatal(err)
			}
		}

		out, errOut, code := capture(t, "update")
		if code != ExitOK {
			t.Fatalf("%s: the update exited %d:\n%s%s", c.name, code, out, errOut)
		}

		target, err := os.Readlink(link)

		switch {
		case c.foreign:
			if got, _ := os.ReadFile(link); string(got) != "somebody else's" || !strings.Contains(errOut, link+" is not conflux's") {
				t.Errorf("%s: the update left %q there, saying:\n%s", c.name, got, errOut)
			}
		case c.onPath:
			if !os.IsNotExist(err) {
				t.Errorf("%s: the update made %s (%v), which root's PATH does not need", c.name, link, err)
			}
		default:
			if err != nil || target != exe || !strings.Contains(out, "Linked "+link) {
				t.Errorf("%s: %s links to %q (%v), want %s, and the update said:\n%s%s", c.name, link, target, err, exe, out, errOut)
			}
		}
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
