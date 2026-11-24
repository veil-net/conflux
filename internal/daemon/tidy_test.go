package daemon

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/config"
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
