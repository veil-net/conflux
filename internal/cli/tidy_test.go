package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/veil-net/conflux/anchor"
	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/pathstest"
	"github.com/veil-net/conflux/internal/privcheck"
	"github.com/veil-net/conflux/internal/service"
)

// oldInstall is a CONFLUX_DIR installation as earlier conflux left it, for an update to find: the
// configuration, the identity and the state, which it keeps, and what it does not -- a set an
// earlier conflux extracted, a staging directory a crashed extraction left, this build's own set
// planted by somebody, its binaries padded to their sizes, stale lock files, an older copy for the
// service with the image Windows moved aside and a copy that never went in place, an atomic write
// that never went in place, the run
// directory's token, marker, pid record and socket directory, a killed ephemeral run's root, and
// beside the conflux the update replaced, a download that never went in place and the image moved
// aside. It returns what is kept, by path, and what the update left beside the conflux it replaced.
func oldInstall(t *testing.T) (d paths.Dirs, kept map[string][]byte, leftovers []string) {
	t.Helper()

	d = pathstest.Dirs(t)

	if err := config.Save(d, &config.Config{Mode: config.ModeProxy, Proxies: []string{"8080=127.0.0.1:3000"},
		Taints: []string{"cfx-old"}}); err != nil {
		t.Fatal(err)
	}

	if err := config.SaveManifest(d, config.Envelope("bWFuaWZlc3Q=")); err != nil {
		t.Fatal(err)
	}

	if err := config.SaveState(d, &config.State{AnchorID: "anchorold", IssuedAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}

	set := filepath.Join(d.Libexec(), anchor.SetID())
	exe := filepath.Join(t.TempDir(), "conflux")
	leftovers = []string{filepath.Join(filepath.Dir(exe), ".conflux-update-123"), exe + ".old"}

	for p, body := range map[string][]byte{
		filepath.Join(d.Libexec(), "0123456789abcdef", binName("anchord")): []byte("an earlier set"),
		filepath.Join(d.Libexec(), ".staging-123", binName("anchord")):     []byte("a crashed extraction"),
		filepath.Join(set, binName("anchord")):                             make([]byte, len(anchor.Anchord())),
		filepath.Join(set, binName("anchorctl")):                           make([]byte, len(anchor.Anchorctl())),
		filepath.Join(d.Libexec(), ".lock"):                                []byte("stale"),
		d.LockFile():                                                       []byte("stale"),
		d.ServeLockFile():                                                  []byte("stale"),
		d.ServiceExecutable():                                              []byte("an earlier conflux"),
		d.ServiceExecutable() + ".old":                                     []byte("an earlier conflux still"),
		filepath.Join(d.State, ".conflux-123"):                             []byte("a copy that never went in place"),
		filepath.Join(d.State, ".tmp-123"):                                 []byte("a write that never went in place"),
		d.TokenFile():                                                      []byte("token"),
		d.ReadyFile():                                                      []byte("ready"),
		d.DaemonPIDFile():                                                  []byte("2147483646\n/nonexistent/anchord\n"),
		filepath.Join(d.DaemonRun(), "sock.lock"):                          nil,
		filepath.Join(paths.EphemeralCandidates()[0], "serve.lock"):        nil,
		exe:          []byte("this conflux"),
		leftovers[0]: []byte("a download"),
		leftovers[1]: []byte("the image moved aside"),
	} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(p, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	was := updateExecutable
	t.Cleanup(func() { updateExecutable = was })

	updateExecutable = func() (string, error) { return exe, nil }

	kept = map[string][]byte{}

	for _, p := range []string{d.ConfigFile(), d.ManifestFile(), d.StateFile()} {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}

		kept[p] = b
	}

	return d, kept, leftovers
}

// TestUpdateLeavesOnlyWhatThisConfluxMakes: update hands the service to the conflux it put in place
// through that conflux's register, the anchor stopped, or its start, the anchor running; and before
// either places or registers anything, it removes what earlier conflux left everywhere conflux keeps
// files, and makes what it removed afresh. What is left is this conflux's alone: this build's set,
// extracted again over the one planted padded to its sizes, under a lock made again; no other set,
// nothing staged; a copy for the service that is this conflux, nothing beside it, nor a write that
// never went in place; an empty run
// directory; no killed run's root; no lock file of the earlier conflux; nothing an update left beside
// the conflux it replaced. The configuration, the identity and the state are as they were.
func TestUpdateLeavesOnlyWhatThisConfluxMakes(t *testing.T) {
	anchortest.Require(t)

	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	for _, verb := range []string{"register", "start"} {
		t.Run(verb, func(t *testing.T) {
			d, kept, leftovers := oldInstall(t)

			mgr := &fakeManager{d: d, restartErr: errStartsNothing}
			standInService(t, mgr)

			out, errOut, code := capture(t, verb)

			want, restarts := ExitOK, 0
			if verb == "start" {
				want, restarts = ExitError, 1
			}

			if code != want || len(mgr.installs) != 1 || mgr.restarts != restarts {
				t.Fatalf("conflux %s exited %d, registered %d times and restarted %d, want %d, once and %d:\n%s%s",
					verb, code, len(mgr.installs), mgr.restarts, want, restarts, out, errOut)
			}

			set := filepath.Join(d.Libexec(), anchor.SetID())

			if got := names(t, d.Libexec()); !slices.Equal(got, []string{".lock", anchor.SetID()}) {
				t.Errorf("%s holds %q, want this build's set and its lock alone", d.Libexec(), got)
			}

			for p, want := range map[string][]byte{
				filepath.Join(set, binName("anchord")):   anchor.Anchord(),
				filepath.Join(set, binName("anchorctl")): anchor.Anchorctl(),
				filepath.Join(d.Libexec(), ".lock"):      {},
			} {
				if b, err := os.ReadFile(p); err != nil || !bytes.Equal(b, want) {
					t.Errorf("%s is not what this conflux makes (%d bytes, %v)", p, len(b), err)
				}
			}

			this, err := service.Executable()
			if err != nil {
				t.Fatal(err)
			}

			if b, _ := os.ReadFile(d.ServiceExecutable()); !bytes.Equal(b, mustRead(t, this)) {
				t.Errorf("%s is not this conflux", d.ServiceExecutable())
			}

			gone := append([]string{d.ServiceExecutable() + ".old", filepath.Join(d.State, ".conflux-123"),
				filepath.Join(d.State, ".tmp-123"), paths.EphemeralCandidates()[0]}, leftovers...)

			for _, p := range gone {
				if _, err := os.Lstat(p); !os.IsNotExist(err) {
					t.Errorf("%s is still there (Lstat: %v)", p, err)
				}
			}

			for _, p := range []string{d.LockFile(), d.ServeLockFile()} {
				if b, err := os.ReadFile(p); err == nil && len(b) > 0 {
					t.Errorf("%s is the earlier conflux's still, holding %q", p, b)
				}
			}

			if got := names(t, d.Run); len(got) > 0 {
				t.Errorf("%s holds %q, which the supervisors before this conflux left", d.Run, got)
			}

			for p, was := range kept {
				if b, err := os.ReadFile(p); err != nil || !bytes.Equal(b, was) {
					t.Errorf("%s changed: %q, %v", p, b, err)
				}
			}

			if !strings.Contains(out, "Removed what earlier conflux left:") {
				t.Errorf("conflux %s did not say what it removed:\n%s", verb, out)
			}
		})
	}
}

// TestAStartOfTheConfluxTheServiceRunsRemovesNothing: a start of the conflux the service already
// runs is no update, and leaves alone what is there, as every start before it did.
func TestAStartOfTheConfluxTheServiceRunsRemovesNothing(t *testing.T) {
	anchortest.Require(t)

	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	d, _, leftovers := oldInstall(t)

	if _, err := service.Place(d); err != nil {
		t.Fatal(err)
	}

	mgr := &fakeManager{d: d, restartErr: errStartsNothing}
	standInService(t, mgr)

	if _, errOut, code := capture(t, "start"); code != ExitError || mgr.restarts != 1 {
		t.Fatalf("conflux start exited %d and restarted %d times:\n%s", code, mgr.restarts, errOut)
	}

	for _, p := range append([]string{filepath.Join(d.Libexec(), "0123456789abcdef"), d.LockFile()}, leftovers...) {
		if _, err := os.Lstat(p); err != nil {
			t.Errorf("a start of the conflux the service runs removed %s: %v", p, err)
		}
	}
}

// names is what dir holds, by name, in order; none where it is not there.
func names(t *testing.T, dir string) []string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}

	var found []string
	for _, e := range entries {
		found = append(found, e.Name())
	}

	return found
}

// binName is an extracted binary's name on this platform.
func binName(base string) string {
	if runtime.GOOS == "windows" {
		return base + ".exe"
	}

	return base
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	return b
}
