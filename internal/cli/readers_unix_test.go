//go:build !windows

package cli

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/anchorctl"
	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/libexec"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/pathstest"
	"github.com/veil-net/conflux/internal/privcheck"
	"github.com/veil-net/conflux/internal/service"
	"github.com/veil-net/conflux/internal/ui"
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
// stopped or removed (readersRefuse); and uninstall removes it, reading and signalling nothing in it and
// following no link it holds (uninstallRemoves). (On Linux, one whose ACL lets another account write it:
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

			if err := os.Chmod(d.Root, c.mode); err != nil {
				t.Fatal(err)
			}

			t.Cleanup(func() { _ = os.Chmod(d.Root, 0o700) })

			readersRefuse(t, d, "anybody may write")
			uninstallRemoves(t, d, "anybody may write")
		})
	}
}

// plantedRoot is a root holding what a reader would read and act on by its name: a configuration
// naming a taint status would print, and a pid record, for a process that is not running, which
// uninstall's reap would take its lock for and stop.
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
// down, renew, update with the boot service installed and a pass-through (peers) -- refuses it, exit 1, naming its root and saying who could write it (why), and leaves
// it as it was: nothing in it read (status prints no configuration), and nothing made, changed or
// removed there, a lock included; the boot service neither registered again, started, stopped nor
// removed; and no conflux downloaded, put in place or asked anything by update.
func readersRefuse(t *testing.T, d paths.Dirs, why string) {
	t.Helper()

	// The release update reads, whose conflux notes what it is asked in asked; and no socket of
	// the caller's, which a pass-through would take instead of d's.
	data, runtimeFolder := paths.SystemData, paths.RuntimeFolder
	rel, exe, asked := releaseAsking(t)
	paths.SystemData, paths.RuntimeFolder = data, runtimeFolder
	t.Setenv(anchorctl.SocketEnv, "")

	// What each command finds, which it leaves as it was: the root, the file update replaces, the
	// release's downloads and what the conflux it puts in place was asked.
	found := func() []string {
		have := tree(t, d.Root)

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

	for _, argv := range [][]string{{"status"}, {"down"}, {"renew"}, {"update"}, {"peers"}} {
		t.Run(argv[0], func(t *testing.T) {
			mgr := &untouched{fakeManager: fakeManager{d: d, restartErr: errStartsNothing}}
			standInService(t, mgr)

			was := found()

			out, errOut, code := capture(t, argv...)
			if code != ExitError || !strings.Contains(errOut, d.Root) || !strings.Contains(errOut, why) {
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

// serveChild runs conflux serve with args, outside systemd, in a child of the test binary (confluxChild),
// which puts its log over its output: what it wrote where the service manager would read it, and its
// exit code.
func serveChild(t *testing.T, args ...string) (out string, code int) {
	t.Helper()

	t.Setenv("NOTIFY_SOCKET", "")

	return confluxChild(t, append([]string{"serve"}, args...)...)
}

// TestServeOpensNoLogInARootItRefuses: serve --log opens its log by name, as root, to append to it,
// so it does that only once EnsureAll has made the root conflux's alone. Under a root EnsureAll
// refuses -- one whose data folder is beneath a file, which cannot be walked -- the file a link at the
// log's name leads to gets nothing, and the refusal goes where the service manager sends serve's output.
func TestServeOpensNoLogInARootItRefuses(t *testing.T) {
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	pathstest.RootedIn(t, filepath.Join(file, "data"))
	log := filepath.Join(t.TempDir(), "conflux.log")

	elsewhere := filepath.Join(t.TempDir(), "elsewhere")
	if err := os.WriteFile(elsewhere, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.Symlink(elsewhere, log); err != nil {
		t.Fatal(err)
	}

	out, code := serveChild(t, "--foreground", "--log", log)
	if code != ExitError || !strings.Contains(out, file) {
		t.Errorf("serve under a root beneath a file exited %d, want %d saying why:\n%s", code, ExitError, out)
	}

	if b, _ := os.ReadFile(elsewhere); len(b) > 0 {
		t.Errorf("serve appended to %s, where a link at its log's name led:\n%s", elsewhere, b)
	}
}

// TestServeWritesItsLogOnceTheRootIsJudged: under a root EnsureAll accepts, what serve --log says
// from then on goes to its log and not where the service manager sends serve's output -- here a
// second supervisor's refusal, the first thing a start can say after EnsureAll, and why serve ends.
// The log is the root's own where the platform keeps one there (macOS, FreeBSD), and beside the root
// elsewhere, where conflux keeps none in it.
func TestServeWritesItsLogOnceTheRootIsJudged(t *testing.T) {
	pathstest.RootedIn(t, t.TempDir())

	d := paths.Default()
	defer holdRoot(t, d)()

	log := d.LogFile()
	if log == "" {
		log = filepath.Join(t.TempDir(), "conflux.log")
	}

	if err := os.MkdirAll(filepath.Dir(log), 0o700); err != nil {
		t.Fatal(err)
	}

	const refusal = "another conflux supervisor is already serving"

	out, code := serveChild(t, "--foreground", "--log", log)
	b, _ := os.ReadFile(log)

	if code != ExitError || !strings.Contains(string(b), refusal) || strings.Contains(out, refusal) {
		t.Errorf("serve beside another supervisor exited %d, want %d, its log holding\n%s\nand its output\n%s",
			code, ExitError, b, out)
	}
}

// uninstallRemoves fails t unless uninstall of the root d, which the readers' check refuses saying
// why, removes it all the same and leaves nothing of it, reading nothing in it: off a terminal and
// without --yes refused, exit 2, with nothing removed, since it cannot say whose identity it would
// destroy; with --yes the boot service removed, the root gone with what it holds, a link planted in it
// to a directory outside it removed as the link, with that directory and what is in it untouched,
// nothing in it printed, and the anchord its pid record names not looked for (reap).
func uninstallRemoves(t *testing.T, d paths.Dirs, why string) {
	t.Helper()

	t.Run("uninstall unconfirmed", func(t *testing.T) {
		if ui.IsTerminal() {
			t.Skip("this test's stdin is a terminal")
		}

		mgr := &untouched{fakeManager: fakeManager{d: d}}
		standInService(t, mgr)

		out, errOut, code := capture(t, "uninstall")
		if code != ExitUsage || !strings.Contains(errOut, "--yes") || mgr.removals > 0 {
			t.Errorf("uninstall of a root %s off a terminal, without --yes, exited %d and removed the boot service %d "+
				"times, want %d naming --yes, nothing removed:\n%s%s", why, code, mgr.removals, ExitUsage, out, errOut)
		}

		if _, err := os.Lstat(d.ConfigFile()); err != nil {
			t.Errorf("uninstall, unconfirmed, removed %s: %v", d.ConfigFile(), err)
		}
	})

	t.Run("uninstall", func(t *testing.T) {
		recordAccounts(t)

		outside := t.TempDir()

		kept := filepath.Join(outside, "kept")
		if err := os.WriteFile(kept, []byte("not conflux's"), 0o600); err != nil {
			t.Fatal(err)
		}

		if err := os.Symlink(outside, filepath.Join(d.Root, ".tmp-planted-link")); err != nil {
			t.Fatal(err)
		}

		mgr := &untouched{fakeManager: fakeManager{d: d}}
		standInService(t, mgr)

		reaped := 0

		defer func(was func(paths.Dirs, time.Duration)) { reap = was }(reap)
		reap = func(paths.Dirs, time.Duration) { reaped++ }

		out, errOut, code := capture(t, "uninstall", "--yes")
		if code != ExitOK {
			t.Fatalf("uninstall of a root %s exited %d, want it removed:\n%s%s", why, code, out, errOut)
		}

		if _, err := os.Lstat(d.Root); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("uninstall left %s, a root %s (Lstat: %v)", d.Root, why, err)
		}

		if b, err := os.ReadFile(kept); err != nil || string(b) != "not conflux's" {
			t.Errorf("the directory a link planted in the root led to lost what is in it: %q, %v", b, err)
		}

		if mgr.removals != 1 || !strings.Contains(out, "  "+d.Root+"\n") || strings.Contains(out, "planted") {
			t.Errorf("uninstall removed the boot service %d times and printed, want it removed once and %s listed:\n%s",
				mgr.removals, d.Root, out)
		}

		if reaped > 0 {
			t.Errorf("uninstall reaped by the pid record of a root %s %d times", why, reaped)
		}
	})
}

// TestAStartRemakesARootNotAsConfluxMakesOne: a root every account may write is not as conflux makes
// one, so a start, which the readers' check sends to tidy rather than read the service's copy there,
// removes it and makes it afresh, the configuration and an earlier set with it: with nothing left to
// start, it exits 78, the root conflux's alone again.
func TestAStartRemakesARootNotAsConfluxMakesOne(t *testing.T) {
	anchortest.Require(t) // it extracts the pair afresh

	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	d := configured(t)

	if _, err := service.PlaceAfresh(d); err != nil {
		t.Fatal(err)
	}

	earlier := filepath.Join(d.Libexec(), "0123456789abcdef")
	if err := os.MkdirAll(earlier, 0o700); err != nil {
		t.Fatal(err)
	}

	pathstest.NotAsConfluxMakesIt(t, d.Root)

	mgr := &fakeManager{d: d, restartErr: errStartsNothing}
	standInService(t, mgr)

	out, errOut, code := capture(t, "start")
	if code != ExitNoConfig {
		t.Fatalf("conflux start of a root every account may write exited %d, want %d:\n%s%s", code, ExitNoConfig, out,
			errOut)
	}

	for _, p := range []string{earlier, d.ConfigFile()} {
		if _, err := os.Lstat(p); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("a start of a root every account may write left %s (Lstat: %v)", p, err)
		}
	}

	if fi, err := os.Stat(d.Root); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("the root a start made afresh is %v (%v), want it at 0700", fi.Mode(), err)
	}
}

// TestAnUpdateStopsTheServiceServingARootNotAsConfluxMakesOne: a root a supervisor serves that is not as
// conflux makes one -- every account may write it -- holds no serve lock conflux reads, yet the
// supervisor still runs from it, so the conflux an update put in place stops the service before it
// removes the root and makes it afresh, and starts it again once it is done.
func TestAnUpdateStopsTheServiceServingARootNotAsConfluxMakesOne(t *testing.T) {
	anchortest.Require(t) // it extracts the pair afresh

	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	for _, verb := range []string{"register", "start"} {
		t.Run(verb, func(t *testing.T) {
			d := configured(t)

			mgr := &stopping{fakeManager: fakeManager{d: d}, running: true, release: serving(t, d)}
			standInService(t, mgr)

			if err := os.Chmod(d.Root, 0o777); err != nil {
				t.Fatal(err)
			}

			stoppedFirst := false
			mgr.asked = func() {
				_, err := os.Lstat(d.ConfigFile())
				stoppedFirst = err == nil
			}

			out, errOut, code := capture(t, verb)
			if mgr.stops != 1 || !stoppedFirst || mgr.restarts != 1 {
				t.Errorf("conflux %s of a root every account may write that a supervisor serves exited %d, stopped the "+
					"service %d times (before the root was made afresh: %v) and started it %d, want once each, the "+
					"stop first:\n%s%s", verb, code, mgr.stops, stoppedFirst, mgr.restarts, out, errOut)
			}
		})
	}
}

// TestAnUpgradeStopsTheServiceBeforeTheRootsAreMade: a conflux put in place by hand or by an install
// script, whose copy for the service is not yet this one, removes what earlier conflux left at the
// first up or proxy, as start does: the service stopped before anything in its roots is made afresh --
// here a bin/ every account may write, which EnsureAll removes and makes again -- and that made afresh
// once it is stopped, the copy this conflux.
func TestAnUpgradeStopsTheServiceBeforeTheRootsAreMade(t *testing.T) {
	anchortest.Require(t) // it extracts the pair afresh

	rootOnLinux(t)

	for name, args := range map[string][]string{
		"up":    {"up", "--taint", "t", "--no-ipv4"},
		"proxy": {"proxy", "8080=127.0.0.1:3000", "--taint", "t", "--no-ipv4"},
	} {
		t.Run(name, func(t *testing.T) {
			d := configured(t)

			planted := filepath.Join(d.Libexec(), "planted")
			if err := os.MkdirAll(d.Libexec(), 0o700); err != nil {
				t.Fatal(err)
			}

			if err := os.WriteFile(planted, []byte("an earlier conflux's"), 0o600); err != nil {
				t.Fatal(err)
			}

			if err := os.Chmod(d.Libexec(), 0o777); err != nil {
				t.Fatal(err)
			}

			mgr := &stopping{fakeManager: fakeManager{d: d, restartErr: errStartsNothing}, running: true,
				release: serving(t, d)}
			standInService(t, mgr)

			// Asked first as the service is stopped, and after that as whether it still has to be started.
			intact, asked := false, false
			mgr.asked = func() {
				if !asked {
					_, err := os.Lstat(planted)
					intact, asked = err == nil, true
				}
			}

			out, errOut, code := capture(t, args...)
			if mgr.stops != 1 || !intact {
				t.Fatalf("conflux %s of an upgraded installation exited %d and stopped the service %d times (before "+
					"%s was made afresh: %v), want once, first:\n%s%s", name, code, mgr.stops, d.Libexec(), intact, out,
					errOut)
			}

			if _, err := os.Lstat(planted); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("conflux %s left %s, which EnsureAll makes afresh (Lstat: %v)", name, planted, err)
			}

			if !service.Placed(d) {
				t.Errorf("conflux %s did not write this conflux as the service's copy", name)
			}
		})
	}
}

// TestAReaderLeavesNothingInTheTemporaryDirectory: a reader of an installation with this build's pair
// not extracted -- status, with the daemon's token or without it, a pass-through to the daemon (peers),
// a pass-through for usage (peers -h) and help -- runs a temporary copy of anchorctl where there is no
// bin directory to extract the pair into, and removes it however it ends; and where there is one,
// extracts the pair there and writes nothing in the temporary directory at all. Either way the temporary
// directory is left as it was found, empty, and the reader ends as anchorctl did -- usage and help 0,
// the pass-through anchorctl's own refusal of a socket nothing listens on, 1 -- never by a panic.
func TestAReaderLeavesNothingInTheTemporaryDirectory(t *testing.T) {
	anchortest.Require(t)

	for _, bin := range []bool{false, true} {
		for _, c := range []struct {
			name  string
			argv  []string
			token bool
			code  int
			said  string
		}{
			{"status", []string{"status"}, true, ExitOK, ""},
			{"status, no token", []string{"status"}, false, ExitOK, ""},
			{"peers", []string{"peers"}, true, 1, "anchorctl:"},
			{"peers -h", []string{"peers", "-h"}, true, ExitOK, ""},
			{"help", []string{"help"}, true, ExitOK, strings.Repeat("─", 72)}, // the rule above anchorctl's half
		} {
			t.Run(fmt.Sprintf("%s, bin %v", c.name, bin), func(t *testing.T) {
				d := pathstest.DirsIn(t, pathstest.ShortRoot(t))

				tmp := pathstest.Temporary(t, t.TempDir())
				t.Setenv(anchorctl.SocketEnv, "")
				t.Setenv(anchorctl.TokenEnv, "")

				if err := config.Save(d, &config.Config{Mode: config.ModeProxy, Taints: []string{"t"},
					APIBaseURL: "https://127.0.0.1:1"}); err != nil {
					t.Fatal(err)
				}

				// A socket's name with nothing behind it, which a reader asks all the same.
				if err := os.MkdirAll(d.DaemonRun(), 0o700); err != nil {
					t.Fatal(err)
				}

				if err := os.WriteFile(d.Socket(), nil, 0o600); err != nil {
					t.Fatal(err)
				}

				if c.token {
					if err := os.WriteFile(d.TokenFile(), []byte("token"), 0o600); err != nil {
						t.Fatal(err)
					}
				}

				if !bin {
					if err := os.Remove(d.Libexec()); err != nil {
						t.Fatal(err)
					}
				}

				var (
					out  string
					code int
				)

				if c.argv[0] == "status" {
					standInService(t, &fakeManager{d: d})
					out, _, code = capture(t, c.argv...)
				} else {
					out, code = confluxChild(t, c.argv...)
				}

				if code != c.code || !strings.Contains(out, c.said) {
					t.Errorf("conflux %s exited %d, want %d, saying %q:\n%s", strings.Join(c.argv, " "), code, c.code,
						c.said, out)
				}

				if left, _ := os.ReadDir(tmp); len(left) > 0 {
					t.Errorf("conflux %s left %v in the temporary directory", strings.Join(c.argv, " "), left)
				}

				if _, err := libexec.Extracted(d); bin && err != nil {
					t.Errorf("conflux %s did not extract the pair into the bin directory: %v", strings.Join(c.argv, " "),
						err)
				}
			})
		}
	}
}

// TestTheServiceStartsAgainInNoRootItRefuses: before the service tidy stopped is started again, its roots
// are held to the readers' check, and the copy of conflux placed afresh where it is not as conflux makes
// one (service.OwnCopy) only where they pass: in a root every account may write, where anybody could have
// put a copy of their own for the service to run as root, nothing is placed, the service is not started,
// and the refusal fails the command.
func TestTheServiceStartsAgainInNoRootItRefuses(t *testing.T) {
	d := pathstest.Dirs(t)

	pathstest.NotAsConfluxMakesIt(t, d.Root)

	mgr := &fakeManager{d: d}

	_, errOut, code := captureOf(t, func() int { return startAgain(d, mgr, true, ExitOK) })
	if code == ExitOK || mgr.restarts > 0 || !strings.Contains(errOut, "anybody may write") {
		t.Errorf("starting the service again in a root every account may write exited %d and started it %d times, "+
			"want the readers' check's refusal, nothing started:\n%s", code, mgr.restarts, errOut)
	}

	if _, err := os.Lstat(d.ServiceExecutable()); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("a copy was placed in a root every account may write (Lstat %s: %v)", d.ServiceExecutable(), err)
	}
}
