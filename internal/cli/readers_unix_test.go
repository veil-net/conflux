//go:build !windows

package cli

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/anchorctl"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/pathstest"
	"github.com/veil-net/conflux/internal/privcheck"
)

// untouched is a boot service installed here that counts what it is asked to do -- register,
// start, stop or remove it -- for a test that nothing is.
type untouched struct {
	fakeManager
	stops, removals int
}

func (m *untouched) Stop() error   { m.stops++; return nil }
func (m *untouched) Remove() error { m.removals++; return nil }

// TestAReaderRefusesARootAnotherAccountMayWrite: whoever may write a root could have put a
// configuration, a pid record, a token or a lock there for conflux to read and act on, so every
// command that reads a root without making it holds it to paths' check before it reads anything in
// it by name: one whose mode lets every account write it, sticky or not -- a name nobody has taken
// yet is anybody's in a sticky directory -- is refused, naming it, with nothing in it read, made,
// stopped or removed (readersRefuse). (On Linux, one whose ACL lets another account write it:
// TestAReaderRefusesARootAnACLLetsAnotherAccountWrite.)
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

// readersRefuse fails t unless each command that reads the root d without making it -- status,
// start, down, renew, update with the boot service installed, a pass-through (peers) and
// uninstall -- refuses it, exit 1, naming its root and saying who could write it (why), and leaves
// it as it was: nothing in it read (status prints no configuration), and nothing made, changed or
// removed there, a lock included; the boot service neither registered again, started, stopped nor
// removed; and the conflux update put in place asked neither to start nor to register it.
func readersRefuse(t *testing.T, d paths.Dirs, why string) {
	t.Helper()

	// The release update reads, whose conflux notes what it is asked in asked; and no socket of
	// the caller's, which a pass-through would take instead of d's.
	root := paths.Root()
	_, asked := releaseAsking(t)
	t.Setenv("CONFLUX_DIR", root)
	t.Setenv(anchorctl.SocketEnv, "")

	held := tree(t, d.State)

	for _, argv := range [][]string{{"status"}, {"start"}, {"down"}, {"renew"}, {"update"}, {"peers"}, {"uninstall", "--yes"}} {
		t.Run(argv[0], func(t *testing.T) {
			mgr := &untouched{fakeManager: fakeManager{d: d, restartErr: errStartsNothing}}
			standInService(t, mgr)

			out, errOut, code := capture(t, argv...)
			if code != ExitError || !strings.Contains(errOut, d.State) || !strings.Contains(errOut, why) {
				t.Errorf("conflux %s of a root %s exited %d, want %d naming it and %q:\n%s",
					argv[0], why, code, ExitError, why, errOut)
			}

			if strings.Contains(out, "planted") {
				t.Errorf("conflux %s read the configuration in a root it refuses:\n%s", argv[0], out)
			}

			if len(mgr.installs)+mgr.restarts+mgr.stops+mgr.removals > 0 {
				t.Errorf("conflux %s registered the boot service %d times, started it %d, stopped it %d and removed it %d",
					argv[0], len(mgr.installs), mgr.restarts, mgr.stops, mgr.removals)
			}

			if now := tree(t, d.State); !slices.Equal(now, held) {
				t.Errorf("conflux %s changed a root it refuses: it holds\n%q\nwhere it held\n%q", argv[0], now, held)
			}

			if b, _ := os.ReadFile(asked); len(b) > 0 {
				t.Errorf("conflux %s asked the conflux update put in place for %q", argv[0], b)
			}
		})
	}
}

// tree is every name under root, root included, with its mode, as Lstat finds it: what a command
// that changes nothing there leaves as it was.
func tree(t *testing.T, root string) []string {
	t.Helper()

	var found []string

	err := filepath.WalkDir(root, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		fi, err := e.Info()
		if err != nil {
			return err
		}

		found = append(found, fmt.Sprintf("%s %v", p, fi.Mode()))

		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	return found
}
