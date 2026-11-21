package cli

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/pathstest"
	"github.com/veil-net/conflux/internal/privcheck"
)

// installedScratch is a CONFLUX_DIR installation in a fresh directory, holding what one does once it
// has run: the configuration, the identity, the state with a given-up record in it, an extracted set
// and the service's copy of conflux, the lock files, the run directory's token, readiness marker and
// pid record, and an ephemeral run's root that a killed run left.
func installedScratch(t *testing.T) paths.Dirs {
	t.Helper()

	d := pathstest.Dirs(t)

	if err := config.Save(d, &config.Config{Mode: config.ModeProxy, Proxies: []string{"8080=127.0.0.1:3000"},
		Taints: []string{"cfx-scratch"}}); err != nil {
		t.Fatal(err)
	}

	if err := config.SaveManifest(d, config.Envelope("bWFuaWZlc3Q=")); err != nil {
		t.Fatal(err)
	}

	if err := config.SaveState(d, &config.State{AnchorID: "anchorscratch", AnchorRefused: "refused for good",
		AnchorRefusedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	for p, body := range map[string]string{
		filepath.Join(d.Libexec(), "0123456789abcdef", "anchord"): "an old set",
		filepath.Join(d.Libexec(), ".lock"):                       "",
		d.ServiceExecutable():                                     "the service's copy",
		d.LockFile():                                              "",
		d.ServeLockFile():                                         "",
		d.TokenFile():                                             "token",
		d.ReadyFile():                                             "ready",
		d.DaemonPIDFile():                                         "2147483646\n/nonexistent/anchord\n",
		filepath.Join(paths.EphemeralCandidates()[0], "serve.lock"): "",
	} {
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	return d
}

// TestUninstallLeavesNothingConfluxMade: uninstall removes everything conflux made, the identity,
// configuration and state included, and keeps nothing for a reinstall; and it removes what it finds
// there without following it. A link planted in a root -- to a directory outside it -- is removed as
// the link, and the directory it leads to, and what is in it, are untouched; a file planted there
// that another account owns is removed as itself. What an update left beside the conflux it
// replaced goes too, and that conflux stays: it is the operator's. It says what it removed. (On
// Windows, with a junction: the same test.)
func TestUninstallLeavesNothingConfluxMade(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	d := installedScratch(t)

	outside := t.TempDir()

	kept := filepath.Join(outside, "kept")
	if err := os.WriteFile(kept, []byte("not conflux's"), 0o600); err != nil {
		t.Fatal(err)
	}

	plantLink(t, filepath.Join(d.State, "planted-link"), outside)
	plantLink(t, filepath.Join(d.Libexec(), "0123456789abcdef", "planted-link"), outside)
	plantForeign(t, filepath.Join(d.State, "planted-foreign"))

	// The conflux an update replaced, with what that update left beside it: a download that never
	// went in place, and the image it moved aside.
	exe := filepath.Join(t.TempDir(), "conflux")
	leftovers := []string{filepath.Join(filepath.Dir(exe), ".conflux-update-123"), exe + ".old"}

	for _, p := range append(leftovers, exe) {
		if err := os.WriteFile(p, []byte("a conflux"), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	defer func(was func() (string, error)) { updateExecutable = was }(updateExecutable)
	updateExecutable = func() (string, error) { return exe, nil }

	mgr := &fakeManager{d: d}
	standInService(t, mgr)

	out, errOut, code := capture(t, "uninstall", "--yes")
	if code != ExitOK {
		t.Fatalf("uninstall exited %d, saying:\n%s%s", code, out, errOut)
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

	for _, p := range leftovers {
		if _, err := os.Lstat(p); !os.IsNotExist(err) {
			t.Errorf("uninstall left %s, which an update left beside the conflux it replaced (Lstat: %v)", p, err)
		}
	}

	if _, err := os.Stat(exe); err != nil {
		t.Errorf("uninstall removed the conflux it was run as: %v", err)
	}

	for _, p := range append(leftovers, d.State) {
		if !strings.Contains(out, "  "+p+"\n") {
			t.Errorf("uninstall did not say it removed %s:\n%s", p, out)
		}
	}
}
