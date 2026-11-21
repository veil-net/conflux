//go:build !windows

package cli

import (
	"fmt"
	"io/fs"
	"os"
	"os/exec"
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
// removed; and no conflux downloaded, put in place or asked anything by update.
func readersRefuse(t *testing.T, d paths.Dirs, why string) {
	t.Helper()

	// The release update reads, whose conflux notes what it is asked in asked; and no socket of
	// the caller's, which a pass-through would take instead of d's.
	root := paths.Root()
	rel, exe, asked := releaseAsking(t)
	t.Setenv("CONFLUX_DIR", root)
	t.Setenv(anchorctl.SocketEnv, "")

	// What each command finds, which it leaves as it was: the root, the file update replaces, the
	// release's downloads and what the conflux it puts in place was asked.
	found := func() []string {
		have := tree(t, d.State)

		for _, f := range []string{exe, asked} {
			b, _ := os.ReadFile(f)
			have = append(have, fmt.Sprintf("%s holding %q", f, b))
		}

		for _, p := range rel.Seen() {
			if strings.Contains(p, "/releases/assets/") {
				have = append(have, "downloaded "+p)
			}
		}

		return have
	}

	for _, argv := range [][]string{{"status"}, {"start"}, {"down"}, {"renew"}, {"update"}, {"peers"}, {"uninstall", "--yes"}} {
		t.Run(argv[0], func(t *testing.T) {
			mgr := &untouched{fakeManager: fakeManager{d: d, restartErr: errStartsNothing}}
			standInService(t, mgr)

			was := found()

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

			if now := found(); !slices.Equal(now, was) {
				t.Errorf("conflux %s, refusing the root, changed\n%q\nwhich was\n%q", argv[0], now, was)
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

// serveArgs, set, makes a test that calls asServe first conflux serve, with these arguments, a line
// each: serve places its log over stdout and stderr, which would be the test binary's, so it runs
// in a child of that binary (serveChild).
const serveArgs = "CONFLUX_TEST_SERVE_ARGS"

// asServe is conflux serve, exiting as it does, where serveArgs is set: serveChild's child.
func asServe() {
	if args := os.Getenv(serveArgs); args != "" {
		os.Exit(Main(append([]string{"conflux", "serve"}, strings.Split(args, "\n")...)))
	}
}

// serveChild runs conflux serve with args, outside systemd, in a child of the test binary running
// t's test, which asServe makes it: what it wrote where the service manager would read it, and
// its exit code.
func serveChild(t *testing.T, args ...string) (out string, code int) {
	t.Helper()

	cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$") //nolint:gosec // this test binary
	cmd.Env = append(os.Environ(), "NOTIFY_SOCKET=", serveArgs+"="+strings.Join(args, "\n"))

	b, err := cmd.CombinedOutput()
	if cmd.ProcessState == nil {
		t.Fatalf("run serve: %v", err)
	}

	return string(b), cmd.ProcessState.ExitCode()
}

// TestServeOpensNoLogInARootItRefuses: serve --log opens its log by name, as root, to append to it,
// so it does that only once EnsureAll has made the root conflux's alone. Under a root EnsureAll
// refuses -- a CONFLUX_DIR in a directory every account may write, where anybody could have put a
// root of their own, with a link at logs/conflux.log -- the file the link leads to gets nothing,
// and the refusal goes where the service manager sends serve's output.
func TestServeOpensNoLogInARootItRefuses(t *testing.T) {
	asServe()

	open := t.TempDir()
	root := filepath.Join(open, "conflux")
	log := filepath.Join(root, "logs", "conflux.log")

	if err := os.MkdirAll(filepath.Dir(log), 0o700); err != nil {
		t.Fatal(err)
	}

	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(elsewhere, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(elsewhere, log); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(open, 0o757); err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = os.Chmod(open, 0o700) })

	out, code := serveChild(t, "--foreground", "--dir", root, "--log", log)
	if code != ExitError || !strings.Contains(out, open) {
		t.Errorf("serve under a root in a directory every account may write exited %d, want %d saying why:\n%s",
			code, ExitError, out)
	}

	if b, _ := os.ReadFile(elsewhere); len(b) > 0 {
		t.Errorf("serve appended to %s, where a link at its log's name led:\n%s", elsewhere, b)
	}
}

// TestServeWritesItsLogOnceTheRootIsJudged: under a root EnsureAll accepts, what serve --log says
// from then on goes to its log and not where the service manager sends serve's output -- here a
// second supervisor's refusal, the first thing a start can say after EnsureAll, and why serve ends.
func TestServeWritesItsLogOnceTheRootIsJudged(t *testing.T) {
	asServe()

	t.Setenv("CONFLUX_DIR", t.TempDir())

	d := paths.Default()
	defer holdRoot(t, d)()

	log := filepath.Join(d.State, "logs", "conflux.log")
	if err := os.MkdirAll(filepath.Dir(log), 0o700); err != nil {
		t.Fatal(err)
	}

	const refusal = "another conflux supervisor is already serving"

	out, code := serveChild(t, "--foreground", "--dir", d.State, "--log", log)
	b, _ := os.ReadFile(log)

	if code != ExitError || !strings.Contains(string(b), refusal) || strings.Contains(out, refusal) {
		t.Errorf("serve beside another supervisor exited %d, want %d, its log holding\n%s\nand its output\n%s",
			code, ExitError, b, out)
	}
}
