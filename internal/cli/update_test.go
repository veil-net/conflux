package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
// release, `latest`, whatever build runs it, and asks nothing first, at a terminal too, where what
// is installed is no dev build: a release, answering `version` as this build does as one, every
// line after the first included, run by a dev build; nothing; a file that does not run, which
// cannot say what it is; and this process, a release.
func TestAPlainUpdateTakesTheRelease(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in conflux is a shell script")
	}

	self, err := service.Executable()
	if err != nil {
		t.Fatal(err)
	}

	newer := []byte("#!/bin/sh\necho 'conflux 9.9.9 (0aea0f77bb77) " + runtime.GOOS + "/" + runtime.GOARCH + "'\n")
	release := versionStandIn(t, "")

	for name, c := range map[string]struct {
		running string                 // the channel of the build running the update
		install func(exe string) error // what is installed at exe
		says    string                 // what the update says of it, exe its verb
	}{
		"a release, run by a dev build": {"dev", func(exe string) error {
			return os.WriteFile(exe, release, 0o755)
		}, "%s is " + version.String() + "."},
		"nothing": {"dev", func(string) error { return nil }, "Nothing is installed at %s."},
		"a file that does not run": {"dev", func(exe string) error {
			return os.WriteFile(exe, []byte("\x7fELF no conflux that runs"), 0o755)
		}, "%s does not run here"},
		"this process, a release": {"", func(exe string) error { return os.Symlink(self, exe) }, "%s is " + version.String() + "."},
	} {
		t.Run(name, func(t *testing.T) {
			asRoot(t, true)
			keepChannel(t)
			answer(t, "") // a terminal nothing is typed at, which would answer a question no

			version.Channel = c.running

			exe := filepath.Join(t.TempDir(), "conflux")
			if err := c.install(exe); err != nil {
				t.Fatal(err)
			}

			asked := serveRelease(t, newer, exe)

			out, errOut, code := capture(t, "update")
			if code != ExitOK || !slices.Equal(*asked, []string{"latest", "download"}) || strings.Contains(out, "[y/N]") ||
				!strings.Contains(out, fmt.Sprintf(c.says, exe)) || !strings.Contains(out, "Updated "+exe+": conflux 9.9.9") {
				t.Errorf("update exited %d, asking for %q:\n%s%s", code, *asked, out, errOut)
			}

			if got, _ := os.ReadFile(exe); string(got) != string(newer) {
				t.Errorf("the executable holds %q after the update", got)
			}
		})
	}
}

// versionStandIn is a stand-in conflux that answers `version` as this build answers it, whole, on
// channel: "dev" for a dev build, "" for a release.
func versionStandIn(t *testing.T, channel string) []byte {
	t.Helper()

	was := version.Channel
	version.Channel = channel

	out, _, code := capture(t, "version")

	version.Channel = was

	if code != ExitOK || strings.Contains(out, "\ndev build: ") != (channel == "dev") {
		t.Fatalf("version, on channel %q, exited %d:\n%s", channel, code, out)
	}

	return []byte("#!/bin/sh\ncat <<'END'\n" + out + "END\n")
}

// installedAt writes body where an update finds the installed conflux, the only file in a
// directory of the test's own, and returns both.
func installedAt(t *testing.T, body []byte) (dir, exe string) {
	t.Helper()

	dir = t.TempDir()
	exe = filepath.Join(dir, "conflux")

	if err := os.WriteFile(exe, body, 0o755); err != nil {
		t.Fatal(err)
	}

	return dir, exe
}

// TestAnUpdateAsksFirst: update asks before it puts one tree's build in place of what may be the
// other's, at a terminal, once the release is read and before anything is downloaded, saying
// first what it means. A plain update asks where the installed conflux is a dev build -- as its
// `version` says, what this build's own says as one, or, where it is this process, as this build
// is one -- the release's anchor pinned to the production tree, where a credential from the dev
// tree does not work. --dev asks of whatever is installed, a dev build's anchor pinned to the dev
// tree, where a credential from the production tree does not work, and is the one question asked
// of an installed dev build. y or yes, in any case, takes the build; any other answer, n and the
// end of input among them, changes nothing, said in a line, and exits 2, as a declined observe or
// uninstall does. Not root, either is refused for privilege before it asks, so the command typed
// again under sudo asks once. --check asks nothing.
func TestAnUpdateAsksFirst(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in conflux is a shell script")
	}

	release, dev := versionStandIn(t, ""), versionStandIn(t, "dev")
	newer := []byte("#!/bin/sh\necho 'conflux 9.9.9 (0aea0f77bb77) " + runtime.GOOS + "/" + runtime.GOARCH + "'\n")

	// What a plain update of a dev build says before it asks.
	plainSays := []string{
		"The newest release is latest (9.9.9), built from 0aea0f77bb77.",
		"is a dev build, whose anchor is pinned to the dev tree", "production tree",
		"the anchor will not start on it", "Install the release? [y/N]",
	}

	for _, q := range []struct {
		name      string
		args      []string        // the update asked
		installed []byte          // what is installed, which it is asked of
		tag       string          // the release it takes
		says      []string        // what it says before it asks
		declined  string          // what it says when declined
		answers   map[string]bool // what is typed, and whether that takes the build
	}{
		{
			name: "a plain update of a dev build", args: []string{"update"}, installed: dev, tag: "latest",
			says:     plainSays,
			declined: "the release was not installed, and nothing changed",
			answers:  map[string]bool{"y\n": true, "Yes\n": true, "n\n": false},
		},
		{
			name: "--dev", args: []string{"update", "--dev"}, installed: release, tag: "dev-latest",
			says: []string{
				"The newest dev build is dev-latest (9.9.9), built from 0aea0f77bb77.",
				"pinned to the dev tree", "production tree", "Install the dev build? [y/N]",
			},
			declined: "the dev build was not installed, and nothing changed",
			answers:  map[string]bool{"y\n": true, "": false},
		},
	} {
		for in, takes := range q.answers {
			t.Run(fmt.Sprintf("%s, answered %q", q.name, in), func(t *testing.T) {
				asRoot(t, true)
				answer(t, in)

				dir, exe := installedAt(t, q.installed)
				asked := serveRelease(t, newer, exe)

				out, errOut, code := capture(t, q.args...)

				for _, want := range q.says {
					if !strings.Contains(out, want) {
						t.Errorf("%s should say %q before it asks; it said:\n%s", q.name, want, out)
					}
				}

				got, _ := os.ReadFile(exe)

				if takes {
					if code != ExitOK || !slices.Equal(*asked, []string{q.tag, "download"}) || string(got) != string(newer) ||
						!strings.Contains(out, "Updated "+exe+": conflux 9.9.9") {
						t.Errorf("%s answered %q exited %d, asking for %q, the executable holding %q:\n%s%s",
							q.name, in, code, *asked, got, out, errOut)
					}

					return
				}

				if code != ExitUsage || !slices.Equal(*asked, []string{q.tag}) || string(got) != string(q.installed) ||
					!strings.Contains(errOut, q.declined) {
					t.Errorf("%s answered %q exited %d, asking for %q, the executable holding %q:\n%s%s",
						q.name, in, code, *asked, got, out, errOut)
				}

				if entries, _ := os.ReadDir(dir); len(entries) != 1 {
					t.Errorf("%s answered %q left %d files where there was one", q.name, in, len(entries))
				}
			})
		}

		t.Run(q.name+", not root", func(t *testing.T) {
			asRoot(t, false)
			answer(t, "y\n")

			_, exe := installedAt(t, q.installed)
			asked := serveRelease(t, newer, exe)

			out, errOut, code := capture(t, q.args...)
			if code != ExitDenied || strings.Contains(out, "[y/N]") || slices.Contains(*asked, "download") ||
				!strings.Contains(errOut, "conflux "+strings.Join(q.args, " ")) {
				t.Errorf("%s, not root, exited %d, asking for %q:\n%s%s", q.name, code, *asked, out, errOut)
			}
		})
	}

	t.Run("a plain update of this process, a dev build", func(t *testing.T) {
		asRoot(t, true)
		keepChannel(t)
		answer(t, "n\n")

		version.Channel = "dev"

		self, err := service.Executable()
		if err != nil {
			t.Fatal(err)
		}

		exe := filepath.Join(t.TempDir(), "conflux")
		if err := os.Symlink(self, exe); err != nil {
			t.Fatal(err)
		}

		asked := serveRelease(t, newer, exe)

		out, errOut, code := capture(t, "update")

		for _, want := range plainSays {
			if !strings.Contains(out, want) {
				t.Errorf("a plain update of this process, a dev build, should say %q before it asks; it said:\n%s", want, out)
			}
		}

		if target, _ := os.Readlink(exe); code != ExitUsage || !slices.Equal(*asked, []string{"latest"}) || target != self {
			t.Errorf("update of this process, a dev build, answered no exited %d, asking for %q, the link reading %q:\n%s%s",
				code, *asked, target, out, errOut)
		}
	})

	t.Run("--check of a dev build", func(t *testing.T) {
		asRoot(t, false)
		answer(t, "y\n")

		_, exe := installedAt(t, dev)
		asked := serveRelease(t, newer, exe)

		out, errOut, code := capture(t, "update", "--check")
		if got, _ := os.ReadFile(exe); code != ExitOK || !slices.Equal(*asked, []string{"latest"}) ||
			strings.Contains(out, "[y/N]") || string(got) != string(dev) {
			t.Errorf("update --check of an installed dev build exited %d, asking for %q:\n%s%s", code, *asked, out, errOut)
		}
	})

	// A dev build updated with --dev is asked --dev's question alone, once: a second would read
	// the end of what is typed, and decline.
	t.Run("--dev of a dev build", func(t *testing.T) {
		asRoot(t, true)
		answer(t, "y\n")

		_, exe := installedAt(t, dev)
		asked := serveRelease(t, newer, exe)

		out, errOut, code := capture(t, "update", "--dev")
		if got, _ := os.ReadFile(exe); code != ExitOK || strings.Count(out, "[y/N]") != 1 ||
			!strings.Contains(out, "Install the dev build? [y/N]") ||
			!slices.Equal(*asked, []string{"dev-latest", "download"}) || string(got) != string(newer) {
			t.Errorf("update --dev of an installed dev build exited %d, asking for %q:\n%s%s", code, *asked, out, errOut)
		}
	})
}

// TestAnUpdateThatAsksIsRefusedOffATerminal: where there is no terminal to ask at, an update that
// would ask is refused, as up refuses an IPv4 nobody can give, whatever stdin holds, which it
// leaves unread: nothing is downloaded and nothing changes. --dev's refusal names --yes, which
// answers its question, for scripts and CI, so --dev --yes takes the newest dev build, `dev-latest`,
// off a terminal too, reading nothing of stdin. A plain update of an installed dev build has no
// way past, and its refusal names none: --yes answers --dev's question alone.
func TestAnUpdateThatAsksIsRefusedOffATerminal(t *testing.T) {
	newer := []byte("#!/bin/sh\necho 'conflux 9.9.9 (0aea0f77bb77) " + runtime.GOOS + "/" + runtime.GOARCH + "'\n")

	for _, c := range []struct {
		name      string
		args      []string
		installed []byte
		standIn   bool     // whether a stand-in conflux, a shell script, has to run
		asked     []string // what the update reads
		refused   string   // what the refusal says; "" where the build is taken
	}{
		{
			name: "a plain update of a dev build", args: []string{"update"},
			installed: versionStandIn(t, "dev"), standIn: true, asked: []string{"latest"},
			refused: "update asks before it installs the release in place of a dev build, and there is no terminal to ask at",
		},
		{
			name: "--dev", args: []string{"update", "--dev"},
			installed: []byte("\x7fELF an older conflux"), asked: []string{"dev-latest"},
			refused: "update --dev asks before it installs a dev build, and there is no terminal to ask at: pass --yes to say so explicitly",
		},
		{
			name: "--dev --yes", args: []string{"update", "--dev", "--yes"},
			installed: versionStandIn(t, ""), standIn: true, asked: []string{"dev-latest", "download"},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.standIn && runtime.GOOS == "windows" {
				t.Skip("the stand-in conflux is a shell script")
			}

			asRoot(t, true)

			in, was := strings.NewReader("y\n"), ui.In
			ui.In = in

			t.Cleanup(func() { ui.In = was })

			dir, exe := installedAt(t, c.installed)
			asked := serveRelease(t, newer, exe)

			out, errOut, code := capture(t, c.args...)
			if !slices.Equal(*asked, c.asked) || strings.Contains(out, "[y/N]") || in.Len() != len("y\n") {
				t.Errorf("%s off a terminal asked for %q, leaving %d bytes of stdin unread:\n%s%s", c.name, *asked, in.Len(), out, errOut)
			}

			got, _ := os.ReadFile(exe)

			if c.refused == "" {
				if code != ExitOK || string(got) != string(newer) {
					t.Errorf("%s off a terminal exited %d, the executable holding %q:\n%s%s", c.name, code, got, out, errOut)
				}

				return
			}

			if code != ExitError || !strings.Contains(errOut, c.refused) || string(got) != string(c.installed) {
				t.Errorf("%s off a terminal exited %d, the executable holding %q:\n%s%s", c.name, code, got, out, errOut)
			}

			// A refusal with no way past names none.
			if !strings.Contains(c.refused, "--yes") && strings.Contains(errOut, "--yes") {
				t.Errorf("%s's refusal names --yes, which does not answer its question:\n%s", c.name, errOut)
			}

			if entries, _ := os.ReadDir(dir); len(entries) != 1 {
				t.Errorf("%s off a terminal left %d files where there was one", c.name, len(entries))
			}
		})
	}
}

// TestADevUpdateWithYesAsksNothing: --yes answers --dev's question, for scripts and CI, so conflux
// update --dev --yes takes the newest dev build, `dev-latest`, without asking at a terminal too
// (off one, TestAnUpdateThatAsksIsRefusedOffATerminal), of an installed release and of an
// installed dev build, whose question is --dev's alone. It answers nothing else: given without
// --dev it is a mistake, said with the usage beneath it, exit 2, before anything is read or
// downloaded, so a plain update of an installed dev build is still asked its own question.
func TestADevUpdateWithYesAsksNothing(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in conflux is a shell script")
	}

	release, dev := versionStandIn(t, ""), versionStandIn(t, "dev")
	newer := []byte("#!/bin/sh\necho 'conflux 9.9.9 (0aea0f77bb77) " + runtime.GOOS + "/" + runtime.GOARCH + "'\n")

	for name, body := range map[string][]byte{"a release": release, "a dev build": dev} {
		t.Run("at a terminal, of "+name, func(t *testing.T) {
			asRoot(t, true)
			answer(t, "n\n") // a question asked would be declined

			_, exe := installedAt(t, body)
			asked := serveRelease(t, newer, exe)

			out, errOut, code := capture(t, "update", "--dev", "--yes")
			if got, _ := os.ReadFile(exe); code != ExitOK || !slices.Equal(*asked, []string{"dev-latest", "download"}) ||
				string(got) != string(newer) || strings.Contains(out, "[y/N]") {
				t.Errorf("update --dev --yes of %s at a terminal exited %d, asking for %q:\n%s%s", name, code, *asked, out, errOut)
			}
		})
	}

	t.Run("without --dev", func(t *testing.T) {
		asRoot(t, true)
		answer(t, "y\n") // what the plain update's question would take

		_, exe := installedAt(t, dev)
		asked := serveRelease(t, newer, exe)

		out, errOut, code := capture(t, "update", "--yes")
		if got, _ := os.ReadFile(exe); code != ExitUsage || out != "" || len(*asked) != 0 || string(got) != string(dev) ||
			!strings.Contains(errOut, "--yes answers the question --dev asks; give --dev too") ||
			!strings.Contains(errOut, "conflux update —") {
			t.Errorf("update --yes of an installed dev build exited %d, asking for %q:\n%s%s", code, *asked, out, errOut)
		}
	})
}

// TestADevCheckAsksNothing: conflux update --dev --check names the newest dev build, and the
// command that installs it, and changes nothing, so it asks nothing, at a terminal too, and needs
// no root; --yes beside it, answering a question never asked, is no mistake. What is installed is
// said: nothing, then a file that does not run.
func TestADevCheckAsksNothing(t *testing.T) {
	asRoot(t, false)
	answer(t, "y\n")

	dir := t.TempDir()
	exe := filepath.Join(dir, "conflux")
	asked := serveRelease(t, []byte("\x7fELF the newest dev build"), exe)
	notConflux := []byte("\x7fELF no conflux that runs")

	for _, installed := range []string{"Nothing is installed at " + exe + ".", exe + " does not run here"} {
		for _, args := range [][]string{{"update", "--dev", "--check"}, {"update", "--dev", "--check", "--yes"}} {
			*asked = nil

			out, errOut, code := capture(t, args...)
			if code != ExitOK || !slices.Equal(*asked, []string{"dev-latest"}) || strings.Contains(out, "[y/N]") ||
				!strings.Contains(out, installed) ||
				!strings.Contains(out, "The newest dev build is dev-latest (9.9.9), built from 0aea0f77bb77.") ||
				!strings.Contains(out, "conflux update --dev") {
				t.Errorf("conflux %s exited %d, asking for %q:\n%s%s", strings.Join(args, " "), code, *asked, out, errOut)
			}
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
