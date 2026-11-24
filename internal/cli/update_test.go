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

	"github.com/veil-net/conflux/internal/privcheck"
	"github.com/veil-net/conflux/internal/update"
	"github.com/veil-net/conflux/internal/version"
)

// serveRelease stands in for conflux's two releases, `latest` and the pre-release `dev-latest`,
// each holding body as this platform's binary, and points `conflux update` at them and at exe
// as the file to replace. It returns the tags an update asked for, in order.
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

	was, wasExe := updateFrom, updateExecutable
	t.Cleanup(func() { updateFrom, updateExecutable = was, wasExe })

	updateFrom = update.Source{API: srv.URL}
	updateExecutable = func() string { return exe }

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

// TestAnUpdateFollowsItsChannel: a release updates to the newest `latest`, and a dev build to
// the newest `dev-latest`, never to the other's: a dev build's anchor is pinned to the dev tree
// and a release's to the production tree, and the credential a machine holds is valid in one
// alone. So nothing is asked first, and no flag crosses from one to the other.
func TestAnUpdateFollowsItsChannel(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return false }

	defer func(was string) { version.Channel = was }(version.Channel)

	exe := filepath.Join(t.TempDir(), "conflux")
	if err := os.WriteFile(exe, []byte("\x7fELF an older build"), 0o755); err != nil {
		t.Fatal(err)
	}

	for channel, want := range map[string]string{"": "latest", "dev": "dev-latest"} {
		version.Channel = channel
		asked := serveRelease(t, []byte("\x7fELF the newest build"), exe)

		out, _, code := capture(t, "update", "--check")
		if code != ExitOK || !slices.Equal(*asked, []string{want}) || !strings.Contains(out, want+" (9.9.9)") {
			t.Errorf("update --check on channel %q exited %d, reading %q:\n%s", channel, code, *asked, out)
		}

		// Nothing more to ask for: it goes on to what any update needs, root, here refused.
		if _, errOut, code := capture(t, "update"); code != ExitDenied {
			t.Errorf("update on channel %q exited %d, want %d:\n%s", channel, code, ExitDenied, errOut)
		}
	}

	if _, _, code := capture(t, "update", "--yes"); code != ExitUsage {
		t.Errorf("update --yes exited %d, want %d: no flag crosses channels", code, ExitUsage)
	}
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

	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

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
