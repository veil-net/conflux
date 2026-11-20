//go:build !windows

package cli

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/pathstest"
	"github.com/veil-net/conflux/internal/privcheck"
	"github.com/veil-net/conflux/internal/service"
)

// removals is a boot manager that counts its removals, for a test that none happens.
type removals struct {
	fakeManager
	removed int
}

func (m *removals) Remove() error { m.removed++; return nil }

// TestAReaderRefusesARootAnotherAccountMayWrite: whoever may write a root could have put a
// configuration, a pid record or a lock there for conflux to read and act on, so status and
// uninstall hold the root to paths' check before they read anything in it by name: one whose mode
// lets every account write it, sticky or not -- a name nobody has taken yet is anybody's in a
// sticky directory -- is refused, naming it, and nothing in it is read, stopped or removed: status
// prints no configuration, and uninstall leaves the service registered and the root, its
// configuration and its pid record where they were, with no lock made beside them. (On Linux, one
// whose ACL lets another account write it: TestAReaderRefusesARootAnACLLetsAnotherAccountWrite.)
func TestAReaderRefusesARootAnotherAccountMayWrite(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	for _, c := range []struct {
		name string
		mode os.FileMode
	}{
		{"every account may write it", 0o757},
		{"every account may write it, sticky", 0o777 | os.ModeSticky},
	} {
		t.Run(c.name, func(t *testing.T) {
			d := plantedRoot(t)

			if err := os.Chmod(d.State, c.mode); err != nil {
				t.Fatal(err)
			}

			t.Cleanup(func() { _ = os.Chmod(d.State, 0o700) })

			readersRefuse(t, d, "anybody may write")
		})
	}
}

// plantedRoot is a root holding what a reader would read and act on by its name: a configuration
// naming a taint status would print, and a pid record, for a process that is not running, which
// uninstall's reap would take its lock for and then remove.
func plantedRoot(t *testing.T) paths.Dirs {
	t.Helper()

	d := pathstest.Dirs(t)

	if err := config.Save(d, &config.Config{Mode: config.ModeProxy, Taints: []string{"planted"}}); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(d.DaemonPIDFile(), []byte("2147483646\n/nonexistent/anchord\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	return d
}

// readersRefuse fails t unless status and uninstall each refuse d, naming its root and saying
// who could write it (why), with nothing in it read or removed.
func readersRefuse(t *testing.T, d paths.Dirs, why string) {
	t.Helper()

	out, errOut, code := capture(t, "status")
	if code != ExitError || !strings.Contains(errOut, d.State) || !strings.Contains(errOut, why) {
		t.Errorf("status of a root %s exited %d, want %d naming it and %q:\n%s", why, code, ExitError, why, errOut)
	}

	if strings.Contains(out, "planted") {
		t.Errorf("status read the configuration in a root it refuses:\n%s", out)
	}

	mgr := &removals{fakeManager: fakeManager{d: d}}

	was := newService
	t.Cleanup(func() { newService = was })

	newService = func() service.Manager { return mgr }

	_, errOut, code = capture(t, "uninstall", "--yes")
	if code != ExitError || !strings.Contains(errOut, d.State) || !strings.Contains(errOut, why) {
		t.Errorf("uninstall of a root %s exited %d, want %d naming it and %q:\n%s", why, code, ExitError, why, errOut)
	}

	if mgr.removed != 0 {
		t.Errorf("uninstall removed the boot service of a root it refuses")
	}

	for _, kept := range []string{d.ConfigFile(), d.DaemonPIDFile()} {
		if _, err := os.Lstat(kept); err != nil {
			t.Errorf("uninstall of a root it refuses removed %s (%v)", kept, err)
		}
	}

	if _, err := os.Lstat(d.ServeLockFile()); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("uninstall of a root it refuses made %s, reaping by its pid record (%v)", filepath.Base(d.ServeLockFile()), err)
	}
}
