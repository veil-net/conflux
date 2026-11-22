package cli

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/pathstest"
	"github.com/veil-net/conflux/internal/privcheck"
)

// TestAFirstSignalStopsAnEphemeralRun: an interrupt, which Ctrl-C sends, or a SIGTERM, sent to an
// ephemeral run's conflux -- here while it enrols, with its anchord up -- ends Main's ctx, and the
// run with it, cleanly: conflux says it stopped and exits 0, the anchord it started is stopped and
// waited for, not left running, and the run's root is gone from the runtime directory it was kept in,
// $XDG_RUNTIME_DIR, which is as it was.
func TestAFirstSignalStopsAnEphemeralRun(t *testing.T) {
	anchortest.Require(t)

	if os.Geteuid() == 0 {
		t.Skip("as root the run hands anchord to the conflux-ephemeral account, which it would make on this host")
	}

	defaultSignals(t)

	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		t.Run(unix.SignalName(sig), func(t *testing.T) {
			bounded(t)

			// A short root rather than TempDir's: the run's control socket lies four levels below it.
			root := pathstest.ShortRoot(t)
			pathstest.Runtime(t, root)

			d, err := paths.EphemeralDirs()
			if err != nil {
				t.Fatal(err)
			}

			// An API that takes the connection and answers nothing, so the run waits on its
			// enrolment, which it makes once its anchord is up, until it is stopped.
			api, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}

			t.Cleanup(func() { _ = api.Close() })

			enrolling := make(chan net.Conn, 1)

			go func() {
				if c, err := api.Accept(); err == nil {
					enrolling <- c
				}
			}()

			var out bytes.Buffer

			// An ephemeral proxy enrolling at that API, run by TestMain (childArgs).
			args := []string{"proxy", "8080=127.0.0.1:3000", "--ephemeral", "--taint", "t", "--api",
				"https://" + api.Addr().String()}

			conflux := exec.Command(os.Args[0], "-test.run=^$") //nolint:gosec // this test binary
			conflux.Env = append(os.Environ(), "XDG_RUNTIME_DIR="+root, childArgs+"="+strings.Join(args, "\n"))
			conflux.Stdout, conflux.Stderr = &out, &out
			conflux.WaitDelay = 5 * time.Second

			if err := conflux.Start(); err != nil {
				t.Fatal(err)
			}

			exited := make(chan error, 1)
			go func() { exited <- conflux.Wait() }()

			// A test that fails kills conflux, then, once it has let go of the root's lock, stops the
			// anchord it recorded, should its parent-death signal not have ended it yet.
			t.Cleanup(func() { daemon.Reap(d, 10*time.Second) })
			t.Cleanup(func() { _ = conflux.Process.Kill() })

			select {
			case c := <-enrolling:
				t.Cleanup(func() { _ = c.Close() })
			case err := <-exited:
				t.Fatalf("the run ended before it enrolled: %v\n%s", err, &out)
			case <-time.After(60 * time.Second):
				overrun(t, "the run had not enrolled 60s after it started")
			}

			b, err := os.ReadFile(d.DaemonPIDFile())
			if err != nil {
				t.Fatalf("the run's anchord, up before it enrols, is not recorded: %v", err)
			}

			pid, err := strconv.Atoi(strings.SplitN(string(b), "\n", 2)[0])
			if err != nil {
				t.Fatal(err)
			}

			if err := conflux.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}

			select {
			case <-exited:
			case <-time.After(childDeadline):
				overrun(t, "the run was sent %v and had not ended %v later", sig, childDeadline)
			}

			if code := conflux.ProcessState.ExitCode(); code != ExitOK || !strings.Contains(out.String(), "Stopped.") {
				t.Errorf("the run, sent %v, ended %v, want stopped and exit 0:\n%s", sig, conflux.ProcessState, &out)
			}

			if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
				t.Errorf("the run's anchord (pid %d) is still there after the run ended: %v", pid, err)

				_ = syscall.Kill(pid, syscall.SIGKILL)
			}

			if _, err := os.Lstat(d.Root); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("the run's root %s is still there after it ended: %v", d.Root, err)
			}

			if left, err := os.ReadDir(root); err != nil || len(left) > 0 {
				t.Errorf("the runtime directory %s, empty before the run, holds %v after it ended (%v)", root, left, err)
			}
		})
	}
}

// handedRun is an ephemeral run prepared from doc, as `--ephemeral --manifest FILE` reads one.
func handedRun(t *testing.T, doc string) *memoryRun {
	t.Helper()

	path := filepath.Join(t.TempDir(), "manifest.b64")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString([]byte(doc))), 0o600); err != nil {
		t.Fatal(err)
	}

	run, code := onLinux{}.start(path)
	if code != ExitOK {
		t.Fatalf("start = exit %d", code)
	}

	return run.(*memoryRun)
}

// TestAnEphemeralRunTakesTheHandedCredentialsAPIAndTaints: as enrol takes them, but into a
// configuration nothing saves -- the API the credential renews against, and the taints it
// grants -- and an --api naming another host is refused, as enrol refuses it.
func TestAnEphemeralRunTakesTheHandedCredentialsAPIAndTaints(t *testing.T) {
	run := handedRun(t, alphaDoc)

	cfg, err := run.fresh("")
	if err != nil {
		t.Fatal(err)
	}

	if cfg.APIBaseURL != "https://api.veilnet.com.au" {
		t.Errorf("APIBaseURL = %q, want the credential's own", cfg.APIBaseURL)
	}

	if want := []string{"brhk-2mq9-tzva-6pjs-k4xe-nw7d-qf"}; !slices.Equal(cfg.Taints, want) {
		t.Errorf("Taints = %v, want the credential's %v", cfg.Taints, want)
	}

	if _, err := run.fresh("https://elsewhere.example"); err == nil {
		t.Error("an --api naming another host than the credential renews against was taken")
	}
}

// TestAnEphemeralRunAsksNothing: the IPv4 is decided by the flags, then the credential, then
// nothing -- never by a question, since an ephemeral run is as often started by a script.
func TestAnEphemeralRunAsksNothing(t *testing.T) {
	alpha := handedRun(t, alphaDoc)
	enrolling := &memoryRun{}

	for _, c := range []struct {
		name  string
		run   *memoryRun
		flag  string
		none  bool
		want  string
		error bool
	}{
		{"the flag", enrolling, "10.128.0.9/24", false, "10.128.0.9/24", false},
		{"none", enrolling, "", true, "", false},
		{"nothing given", enrolling, "", false, "", false},
		{"a credential with none", alpha, "", false, "", false},
		{"both", enrolling, "10.128.0.9", true, "", true},
		{"a bad one", enrolling, "not an address", false, "", true},
	} {
		cfg := &config.Config{}

		err := c.run.ipv4(cfg, c.flag, c.none)
		if (err != nil) != c.error {
			t.Errorf("%s: err = %v, want error %v", c.name, err, c.error)

			continue
		}

		if c.error {
			continue
		}

		if cfg.IPv4 == nil || *cfg.IPv4 != c.want {
			t.Errorf("%s: IPv4 = %v, want %q, decided", c.name, cfg.IPv4, c.want)
		}
	}
}

// TestAnEphemeralProxyNeedsNoRoot: userspace needs no privilege, and an ephemeral run registers
// nothing that would, so proxy runs as anybody; a TUN, and observing, still need root.
func TestAnEphemeralProxyNeedsNoRoot(t *testing.T) {
	was := privcheck.Elevated
	privcheck.Elevated = func() bool { return false }

	t.Cleanup(func() { privcheck.Elevated = was })

	run := &memoryRun{}

	if err := run.root(&config.Config{}, nil); err != nil {
		t.Errorf("an unprivileged ephemeral proxy: %v", err)
	}

	if err := run.root(&config.Config{Observer: &config.Observer{}}, nil); err == nil {
		t.Error("an unprivileged ephemeral proxy that observes was let through")
	}

	if _, errOut, code := capture(t, "up", "--ephemeral"); code != ExitDenied {
		t.Errorf("an unprivileged ephemeral up exited %d, want %d:\n%s", code, ExitDenied, errOut)
	}
}

// hangupChild, set to a signal's number, makes TestNohupHoldsOffAnEphemeralRunsHangup's test
// binary the conflux it runs: an ephemeral run's, on a context Main's signals end, that sends
// itself a hangup and says whether the hangup ended the run, ends it by SIGTERM where it did not,
// as Main's ctx is ended, and then sends itself the signal named and says if it lived on.
const hangupChild = "CONFLUX_TEST_HANGUP_CHILD"

// TestNohupHoldsOffAnEphemeralRunsHangup: an ephemeral run in a terminal that is closed stops
// cleanly on the hangup, and a second signal, not waited for -- a hangup, SIGTERM or an
// interrupt, each of which ended the run's context until then -- ends conflux at once. One
// started under nohup, which ignores SIGHUP so that what it runs outlives the terminal, is ended
// by neither hangup; stopped by SIGTERM, it is ended at once by a second SIGTERM or interrupt, as
// any run is.
func TestNohupHoldsOffAnEphemeralRunsHangup(t *testing.T) {
	if second := os.Getenv(hangupChild); second != "" {
		n, err := strconv.Atoi(second)
		if err != nil {
			fmt.Println(err)
			os.Exit(2)
		}

		// Main's ctx, which SIGINT ends as well as SIGTERM: this child was started catching it
		// (defaultSignals).
		parent, stopParent := signalContext()
		defer stopParent()

		ctx, stop := hangupContext(parent)
		defer stop()

		secondSignalEnds(ctx)

		send := func(sig syscall.Signal) {
			if err := syscall.Kill(os.Getpid(), sig); err != nil {
				fmt.Println(err)
				os.Exit(2)
			}
		}

		send(syscall.SIGHUP)

		select {
		case <-ctx.Done():
			fmt.Println("ended")
		case <-time.After(300 * time.Millisecond):
			fmt.Println("held")

			// Held off, the run ends by another signal, as Main's ctx does.
			send(syscall.SIGTERM)

			select {
			case <-ctx.Done():
			case <-time.After(10 * time.Second):
				fmt.Println("and not ended by SIGTERM")
				os.Exit(2)
			}
		}

		// Then, once the handlers have gone, the second signal.
		time.Sleep(100 * time.Millisecond)
		send(syscall.Signal(n))
		time.Sleep(300 * time.Millisecond)
		fmt.Println("lived on")

		os.Exit(0)
	}

	defaultSignals(t)

	nohup, err := exec.LookPath("nohup")
	if err != nil {
		t.Fatal(err)
	}

	// Every signal that is forwarded, as the second, under each: what the run says of the hangup,
	// and the signal under starts it ignoring, the one second signal that leaves it running.
	for _, tc := range []struct {
		under   []string
		hangup  string
		ignored os.Signal
	}{
		{nil, "ended", nil},
		{[]string{nohup}, "held", syscall.SIGHUP},
	} {
		for _, s := range forwarded {
			second := s.(syscall.Signal)

			want, wantEnded := tc.hangup, s != tc.ignored
			if !wantEnded {
				want += "\nlived on"
			}

			bounded(t)

			argv := append(slices.Clone(tc.under), os.Args[0], "-test.run=^TestNohupHoldsOffAnEphemeralRunsHangup$")

			ctx, cancel := context.WithTimeout(t.Context(), childDeadline)

			conflux := exec.CommandContext(ctx, argv[0], argv[1:]...) //nolint:gosec // this test binary
			conflux.Env = append(os.Environ(), hangupChild+"="+strconv.Itoa(int(second)))
			conflux.Dir = t.TempDir() // where nohup would put nohup.out, had it a terminal to redirect
			conflux.WaitDelay = 5 * time.Second

			out, err := conflux.Output()
			late := ctx.Err() != nil

			cancel()

			if late {
				overrun(t, "%v, %v second: the run was still going after %v:\n%s", tc.under, second, childDeadline, out)
			}
			if got := strings.TrimSpace(string(out)); got != want {
				t.Errorf("%v, %v second: the run said %q (%v), want %q", tc.under, second, got, err, want)
			}

			ws, _ := conflux.ProcessState.Sys().(syscall.WaitStatus)
			if ended := ws.Signaled() && ws.Signal() == second; ended != wantEnded || (!ended && err != nil) {
				t.Errorf("%v, %v second: conflux ended %v, want ended by it: %v", tc.under, second, conflux.ProcessState, wantEnded)
			}
		}
	}
}

// TestStatusAsksWhatItReports: status asks the machine's daemon for its export, which it
// reports, and an ephemeral run's daemon only for its status, since nothing of that run's
// export is reported; and it reads the last anchord's privilege record for both things it
// says of it -- who anchord runs as, and the anchor directory a member's Subnets order is
// kept in.
func TestStatusAsksWhatItReports(t *testing.T) {
	anchortest.Require(t)

	logs := t.TempDir()
	machineLog, ephemeralLog := filepath.Join(logs, "machine"), filepath.Join(logs, "ephemeral")

	d := pathstest.Dirs(t)

	// A live ephemeral run beside the machine's own anchor: its lock held, and marked up by a
	// process that runs -- this one.
	e := startingEphemeral(t)
	if err := daemon.MarkReady(e, "anchorephemeral"); err != nil {
		t.Fatal(err)
	}

	runningStandIn(t, e, ephemeralLog)
	runningStandIn(t, d, machineLog)

	if err := config.Save(d, &config.Config{Mode: config.ModeProxy, Proxies: []string{"8080=127.0.0.1:3000"}, Taints: []string{"t"},
		Export: &config.Export{Enabled: true, Endpoint: "collector.example:4317", Flows: true}}); err != nil {
		t.Fatal(err)
	}

	// anchord was last given root's anchor directory, though the account's is there too, and
	// the order is in root's.
	for _, dir := range []string{d.AnchorDir(), d.RootAnchorDir()} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	order := `{"subnets": ["10.9.0.0/24"], "by": "anchormember", "at": "2026-11-20T00:00:00Z"}`
	if err := os.WriteFile(paths.SubnetsOrderFile(d.RootAnchorDir()), []byte(order), 0o600); err != nil {
		t.Fatal(err)
	}

	priv, err := json.Marshal(daemon.Privilege{As: "root", Why: "a firewall only root may change", Dir: d.RootAnchorDir()})
	if err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(d.PrivilegeFile(), priv, 0o600); err != nil {
		t.Fatal(err)
	}

	out, errOut, code := capture(t, "status")
	if code != ExitOK {
		t.Fatalf("status exited %d:\n%s%s", code, out, errOut)
	}

	for log, want := range map[string][]string{machineLog: {"export", "status"}, ephemeralLog: {"status"}} {
		b, _ := os.ReadFile(log)

		// Asked side by side, so in either order.
		asked := strings.Fields(string(b))
		slices.Sort(asked)

		if !slices.Equal(asked, want) {
			t.Errorf("the %s daemon was asked %q, want %q", filepath.Base(log), asked, want)
		}
	}

	for _, want := range []string{
		"set by anchorctl export — an override",
		"10.9.0.0/24 — set by an order from anchormember",
		"root — a firewall only root may change",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status should say %q; it said:\n%s", want, out)
		}
	}
}

// TestUninstallLeavesALiveRun: a live ephemeral run as root runs as the account uninstall removes, so
// while one is live uninstall refuses, exit 2, naming it, before anything is asked or removed, and again
// once the question is answered, for one started as it was asked; and one that starts once uninstall has
// begun -- here as the boot service is removed -- is left running, with its root and the account it runs
// as, and uninstall says so, exit 1, listing what it removed all the same.
func TestUninstallLeavesALiveRun(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	t.Run("live as uninstall begins", func(t *testing.T) {
		d := oldInstall(t).d
		e := ephemeralRoot(t)
		t.Cleanup(holdRoot(t, e))

		mgr := &removing{fakeManager: fakeManager{d: d}}
		standInService(t, mgr)

		out, errOut, code := capture(t, "uninstall", "--yes")
		if code != ExitUsage || !strings.Contains(errOut, e.Root) {
			t.Errorf("uninstall beside a live run exited %d, want %d naming %s:\n%s%s", code, ExitUsage, e.Root,
				out, errOut)
		}

		if _, err := os.Lstat(d.ConfigFile()); mgr.removals > 0 || err != nil {
			t.Errorf("uninstall beside a live run removed the boot service %d times, and %s (Lstat: %v)",
				mgr.removals, d.ConfigFile(), err)
		}
	})

	t.Run("live once asked", func(t *testing.T) {
		d := oldInstall(t).d
		e := ephemeralRoot(t)

		defer func(was func(paths.Dirs, error, bool) bool) { confirm = was }(confirm)
		confirm = func(paths.Dirs, error, bool) bool {
			t.Cleanup(holdRoot(t, e))

			return true
		}

		mgr := &removing{fakeManager: fakeManager{d: d}}
		standInService(t, mgr)

		out, errOut, code := capture(t, "uninstall", "--yes")
		if code != ExitUsage || !strings.Contains(errOut, e.Root) {
			t.Errorf("uninstall beside a run started as it asked exited %d, want %d naming %s:\n%s%s", code, ExitUsage,
				e.Root, out, errOut)
		}

		if _, err := os.Lstat(d.ConfigFile()); mgr.removals > 0 || err != nil {
			t.Errorf("uninstall beside a run started as it asked removed the boot service %d times, and %s (Lstat: %v)",
				mgr.removals, d.ConfigFile(), err)
		}
	})

	t.Run("started since", func(t *testing.T) {
		d := oldInstall(t).d
		e := ephemeralRoot(t)

		mgr := &removing{fakeManager: fakeManager{d: d}, then: func() { t.Cleanup(holdRoot(t, e)) }}
		standInService(t, mgr)

		accounts := recordAccounts(t)

		out, errOut, code := capture(t, "uninstall", "--yes")
		if code != ExitError || !strings.Contains(errOut, e.Root) || !strings.Contains(errOut, "left running") {
			t.Errorf("uninstall with a run started as it began exited %d, want %d naming %s, left running:\n%s%s",
				code, ExitError, e.Root, out, errOut)
		}

		if _, err := os.Lstat(e.ServeLockFile()); err != nil {
			t.Errorf("uninstall removed the root of a live run: %v", err)
		}

		if !strings.Contains(out, "  the boot service\n") {
			t.Errorf("uninstall, failing, did not say what it had removed:\n%s", out)
		}

		if !slices.Equal(*accounts, []bool{false}) {
			t.Errorf("uninstall removed the accounts anchord ran as %v, want once, the ephemeral run's kept", *accounts)
		}
	})
}

// TestNoInstallationTouchesTheEphemeralRoot: an ephemeral run's root is in the runtime folder, which the
// system empties at boot, and not the installation's: what earlier conflux left is removed by register
// (tidy), and everything conflux made by uninstall, and a killed run's root is left as it was by both.
func TestNoInstallationTouchesTheEphemeralRoot(t *testing.T) {
	defer func(was func() bool) { privcheck.Elevated = was }(privcheck.Elevated)
	privcheck.Elevated = func() bool { return true }

	for _, verb := range [][]string{{"register"}, {"uninstall", "--yes"}} {
		t.Run(verb[0], func(t *testing.T) {
			d := pathstest.Dirs(t)
			e := ephemeralRoot(t)

			if err := os.Mkdir(e.Root, 0o700); err != nil {
				t.Fatal(err)
			}

			lock := e.ServeLockFile()
			if err := os.WriteFile(lock, nil, 0o600); err != nil {
				t.Fatal(err)
			}

			standInService(t, &fakeManager{d: d})
			recordAccounts(t)

			if out, errOut, code := capture(t, verb...); code != ExitOK {
				t.Fatalf("conflux %s exited %d:\n%s%s", verb[0], code, out, errOut)
			}

			if _, err := os.Lstat(lock); err != nil {
				t.Errorf("conflux %s removed %s, a killed ephemeral run's root, which no installation touches: %v",
					verb[0], e.Root, err)
			}
		})
	}
}
