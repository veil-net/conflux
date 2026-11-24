package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
)

// TestTidyKeepsOnlyWhatIsConfluxsAndAnchors: the root, as a start puts it back, and both
// anchor directories, before each anchord starts, hold what conflux and anchor put there and
// nothing else; a temporary file young enough to be another conflux's write in progress is
// left. The run directory a start empties whole (TestAStartEmptiesTheRunDirectory).
func TestTidyKeepsOnlyWhatIsConfluxsAndAnchors(t *testing.T) {
	s := &Supervisor{Dirs: dirs(t)}
	d := s.Dirs

	for _, dir := range []string{d.AnchorDir(), d.RootAnchorDir(), filepath.Join(d.AnchorDir(), "knowledge")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	files := map[string]bool{ // path: kept
		d.ConfigFile(): true, d.StateFile(): true, d.ManifestFile(): true, d.DaemonConfigFile(): true,
		d.PrivilegeFile(): true, d.LockFile(): true, d.ServeLockFile(): true, d.ServiceExecutable(): true,
		d.ServiceExecutable() + ".old":                      true,
		filepath.Join(d.Root, "stray"):                      false,
		filepath.Join(d.Root, ".tmp-123"):                   true,
		filepath.Join(d.Root, ".conflux-123"):               true,
		filepath.Join(d.AnchorDir(), "bootstrap.json"):      true,
		filepath.Join(d.AnchorDir(), "realmlinks"):          true,
		filepath.Join(d.AnchorDir(), "subnets.json"):        true,
		filepath.Join(d.AnchorDir(), "knowledge", "01-x-y"): true,
		filepath.Join(d.AnchorDir(), "stray"):               false,
		filepath.Join(d.AnchorDir(), ".realmlinks-1.tmp"):   false,
		filepath.Join(d.RootAnchorDir(), "bootstrap.json"):  true,
		filepath.Join(d.RootAnchorDir(), "stray"):           false,
	}

	for path := range files {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	// An atomic write's and the service copy's, each left by a crash an hour and more ago.
	for _, name := range []string{".tmp-old", ".conflux-old"} {
		stale := filepath.Join(d.Root, name)
		if err := os.WriteFile(stale, nil, 0o600); err != nil {
			t.Fatal(err)
		}

		then := time.Now().Add(-2 * time.Hour)
		if err := os.Chtimes(stale, then, then); err != nil {
			t.Fatal(err)
		}

		files[stale] = false
	}

	if err := s.tidyRoot(); err != nil {
		t.Fatalf("tidyRoot: %v", err)
	}

	if err := s.tidyAnchorDirs(); err != nil {
		t.Fatalf("tidyAnchorDirs: %v", err)
	}

	for path, kept := range files {
		if _, err := os.Lstat(path); (err == nil) != kept {
			t.Errorf("%s: kept = %v, want %v", path, err == nil, kept)
		}
	}
}

// TestAStartThatStopsPutsTheRootBack: the root is put back at every start, one that then stops
// included -- nothing configured, which exits 78, and a conflux.json refused for good, which exits
// 70: what is neither conflux's nor anchor's goes, and the root's own files get their modes, and
// on Windows their DACLs, back. Their modes and owners alone: a refused file keeps the bytes it
// was written with.
func TestAStartThatStopsPutsTheRootBack(t *testing.T) {
	for name, tc := range map[string]struct {
		config string // conflux.json, or none
		stops  func(error) bool
	}{
		"with nothing configured": {stops: func(err error) bool { return errors.Is(err, ErrNotConfigured) }},
		"refusing its configuration": {config: "{not json", stops: func(err error) bool {
			return Permanent(err) && !errors.Is(err, ErrNotConfigured)
		}},
	} {
		t.Run(name, func(t *testing.T) {
			s := &Supervisor{Dirs: dirs(t)}
			d := s.Dirs

			files := map[string]string{d.ManifestFile(): "the identity"}
			if tc.config != "" {
				files[d.ConfigFile()] = tc.config
			}

			for path, content := range files {
				if err := config.WriteFileAtomic(path, []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}

				widen(t, path)
			}

			stray := filepath.Join(d.Root, "stray")
			if err := os.WriteFile(stray, nil, 0o600); err != nil {
				t.Fatal(err)
			}

			if err := s.Run(t.Context()); !tc.stops(err) {
				t.Fatalf("Run = %v", err)
			}

			if _, err := os.Lstat(stray); err == nil {
				t.Error("a stray file outlived the start")
			}

			for path, content := range files {
				if !restored(path) {
					t.Errorf("%s was not given back its mode, or to SYSTEM and the Administrators", path)
				}

				if got, _ := os.ReadFile(path); string(got) != content {
					t.Errorf("%s was rewritten: %q", path, got)
				}
			}
		})
	}
}

// TestRemoveExcept: removeExcept keeps what keep keeps, a kept directory whole; takes a
// directory that is not there for one holding nothing; removes a link, to outside the directory
// or to an entry in it, as a link, what it leads to untouched; and goes on past an entry that
// will not go, removing the rest and naming that one once, as RemoveEphemeralRoot hands it on.
func TestRemoveExcept(t *testing.T) {
	if err := removeExcept(filepath.Join(t.TempDir(), "missing"), nothing); err != nil {
		t.Errorf("a missing directory: %v, want nothing to remove", err)
	}

	outside := t.TempDir()
	secret := filepath.Join(outside, "secret")

	dir := t.TempDir()

	for _, sub := range []string{"keptdir", "straydir"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	files := map[string]string{
		secret: "outside's", filepath.Join(dir, "kept"): "kept's", filepath.Join(dir, "keptdir", "inner"): "inner's",
		filepath.Join(dir, "stray"): "", filepath.Join(dir, "straydir", "inner"): "",
	}
	for path, content := range files {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	for link, target := range map[string]string{
		"out": outside, "outfile": secret, // out of the directory: a directory and a file
		"in": "kept", // to an entry in it, which stays
	} {
		if err := os.Symlink(target, filepath.Join(dir, link)); err != nil {
			t.Fatal(err)
		}
	}

	if err := removeExcept(dir, named("kept", "keptdir")); err != nil {
		t.Fatalf("removeExcept: %v", err)
	}

	for _, name := range []string{"stray", "straydir", "out", "outfile", "in"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err == nil {
			t.Errorf("%s was not removed", name)
		}
	}

	for path, content := range files {
		if strings.Contains(path, "stray") {
			continue
		}

		if got, err := os.ReadFile(path); err != nil || string(got) != content {
			t.Errorf("%s = %q, %v; want %q left as it was", path, got, err, content)
		}
	}

	// An entry that will not go, between two that must.
	d := paths.Dirs{Root: t.TempDir()}
	held := filepath.Join(d.Root, "held")

	for _, path := range []string{filepath.Join(d.Root, "a"), held, filepath.Join(d.Root, "z"), d.ServeLockFile()} {
		if err := os.WriteFile(path, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	stuck(t, held)

	err := removeExcept(d.Root, named(filepath.Base(d.ServeLockFile())))
	if err == nil || strings.Count(err.Error(), held) != 1 {
		t.Errorf("removeExcept = %v, want an error naming %s once", err, held)
	}

	for _, name := range []string{"a", "z"} {
		if _, err := os.Lstat(filepath.Join(d.Root, name)); err == nil {
			t.Errorf("%s was left beside the entry that would not go", name)
		}
	}

	if err := RemoveEphemeralRoot(d, func() {}); err == nil || strings.Count(err.Error(), held) != 1 ||
		strings.Contains(err.Error(), "remove "+d.Root+": ") {
		t.Errorf("RemoveEphemeralRoot = %v, want removeExcept's error as it was, naming %s once", err, held)
	}
}
