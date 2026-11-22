//go:build !windows

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/veil-net/conflux/internal/anchorctl"
	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/flock"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/pathstest"
	"github.com/veil-net/conflux/internal/ui"
)

// standInDir, set, makes the test binary the conflux TestASignalToConfluxReachesItsAnchorctl
// runs, whose anchorctl is a stand-in in a temporary directory made under it. standInTrap
// says whether the stand-in traps the signal, and where it records which one it was sent.
const (
	standInDir  = "CONFLUX_TEST_STAND_IN_DIR"
	standInTrap = "CONFLUX_TEST_STAND_IN_TRAP"
	standInPID  = "CONFLUX_TEST_STAND_IN_PID"
)

// standIn is an anchorctl that runs until it is signalled: it records its PID, and, trapping,
// which of the forwarded signals it was sent, exiting 7.
var standIn = func() string {
	traps := make([]string, len(forwarded))
	for i, s := range forwarded {
		traps[i] = trapName(s.(syscall.Signal))
	}

	return `#!/bin/sh
if [ -n "$` + standInTrap + `" ]; then
	for s in ` + strings.Join(traps, " ") + `; do
		trap "echo $s > \"\$` + standInTrap + `\"; exit 7" $s
	done
fi
echo $$ > "$` + standInPID + `.tmp" && mv "$` + standInPID + `.tmp" "$` + standInPID + `"
while :; do sleep 0.05; done
`
}()

// TestASignalToConfluxReachesItsAnchorctl: the anchorctl conflux runs as a child, a temporary copy
// (here a stand-in, for a socket the user named), is sent what conflux's PID alone is sent -- a
// kill, a service manager's stop, a hangup -- as it would be had conflux replaced itself with it.
// conflux ends as anchorctl ends, by its exit code or by the signal, and its temporary copy goes
// with it.
func TestASignalToConfluxReachesItsAnchorctl(t *testing.T) {
	if dir := os.Getenv(standInDir); dir != "" {
		readersAnchorctl = func(context.Context) (string, func(), error) {
			tmp, err := os.MkdirTemp(dir, "conflux-usage-")
			if err != nil {
				return "", nil, err
			}

			bin := filepath.Join(tmp, "anchorctl")

			return bin, func() { _ = os.RemoveAll(tmp) }, os.WriteFile(bin, []byte(standIn), 0o700)
		}

		os.Exit(Main([]string{"conflux", "peers", "-socket", "unused"}))
	}

	defaultSignals(t)

	// Each signal that is forwarded, which the stand-in traps, and SIGTERM again, which it does
	// not, so that it ends anchorctl, and conflux after it, by its default action.
	type signalCase struct {
		sig  syscall.Signal
		trap bool
	}

	cases := make([]signalCase, 0, len(forwarded)+1)
	for _, s := range forwarded {
		cases = append(cases, signalCase{s.(syscall.Signal), true})
	}

	for _, tc := range append(cases, signalCase{syscall.SIGTERM, false}) {
		t.Run(tc.sig.String()+map[bool]string{true: ", trapped", false: ", not trapped"}[tc.trap], func(t *testing.T) {
			dir, state := t.TempDir(), t.TempDir()
			pidFile, trapFile := filepath.Join(state, "pid"), ""

			env := append(os.Environ(), standInDir+"="+dir, standInPID+"="+pidFile)
			if tc.trap {
				trapFile = filepath.Join(state, "trapped")
				env = append(env, standInTrap+"="+trapFile)
			}

			conflux := exec.Command(os.Args[0], "-test.run=^TestASignalToConfluxReachesItsAnchorctl$") //nolint:gosec // this test binary
			conflux.Env = env

			if err := conflux.Start(); err != nil {
				t.Fatal(err)
			}

			exited := make(chan error, 1)
			go func() { exited <- conflux.Wait() }()

			pid := waitForPID(t, pidFile, exited)

			// Whatever happens, nothing is left running.
			t.Cleanup(func() {
				_ = syscall.Kill(pid, syscall.SIGKILL)
				_ = conflux.Process.Kill()
			})

			if err := conflux.Process.Signal(tc.sig); err != nil {
				t.Fatal(err)
			}

			select {
			case <-exited:
			case <-time.After(10 * time.Second):
				t.Fatalf("conflux was sent %v and had not ended 10s later", tc.sig)
			}

			ws, _ := conflux.ProcessState.Sys().(syscall.WaitStatus)

			switch {
			case tc.trap:
				if b, _ := os.ReadFile(trapFile); strings.TrimSpace(string(b)) != trapName(tc.sig) {
					t.Errorf("the stand-in was not sent %v: it recorded %q", tc.sig, b)
				}

				if code := conflux.ProcessState.ExitCode(); code != 7 {
					t.Errorf("conflux ended %v, want the stand-in's exit code, 7", conflux.ProcessState)
				}
			case !ws.Signaled() || ws.Signal() != tc.sig:
				t.Errorf("conflux ended %v, want ended by %v as the stand-in was", conflux.ProcessState, tc.sig)
			}

			if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
				t.Errorf("the stand-in (pid %d) is still running after conflux ended: %v", pid, err)
			}

			if left, _ := os.ReadDir(dir); len(left) > 0 {
				t.Errorf("conflux left its temporary anchorctl behind: %d entries in %s", len(left), dir)
			}
		})
	}
}

// TestAPassThroughToConfluxsDaemonReplacesConflux: a pass-through to conflux's own daemon runs the
// installation's extraction in conflux's place: the anchorctl it runs, here a stand-in planted as this
// build's set, has as its parent the test binary, which started conflux, and not conflux.
func TestAPassThroughToConfluxsDaemonReplacesConflux(t *testing.T) {
	anchortest.Require(t)

	d := pathstest.Dirs(t)
	looksRunning(t, d)

	t.Setenv(anchorctl.SocketEnv, "")
	t.Setenv(anchorctl.TokenEnv, "")

	parent := filepath.Join(t.TempDir(), "ppid")
	plantSet(t, d, "echo $PPID > '"+parent+"'")

	out, code := confluxChild(t, "peers")

	b, err := os.ReadFile(parent)
	if ppid, _ := strconv.Atoi(strings.TrimSpace(string(b))); code != ExitOK || ppid != os.Getpid() {
		t.Errorf("conflux peers exited %d, its anchorctl's parent %d (%v), want 0 and this test binary, %d, which "+
			"started conflux:\n%s", code, ppid, err, os.Getpid(), out)
	}
}

// placedArgs, set, makes TestOnlyATemporaryCopyRunsAsAChild's test binary the conflux it runs, with
// these arguments, a line each, its readers' anchorctl the stand-in placedStandIn names: the
// installation's extraction, with no done, or, with placedTemporary set, a temporary copy.
const (
	placedArgs      = "CONFLUX_TEST_PLACED_ARGS"
	placedStandIn   = "CONFLUX_TEST_PLACED_STAND_IN"
	placedTemporary = "CONFLUX_TEST_PLACED_TEMPORARY"
)

// TestOnlyATemporaryCopyRunsAsAChild: a pass-through to a socket the user named, or for usage, whose
// anchorctl is the installation's extraction replaces conflux with it, as one to conflux's daemon does --
// the stand-in runs as conflux's own PID -- and one whose anchorctl is a temporary copy runs it as a child,
// to remove it afterwards.
func TestOnlyATemporaryCopyRunsAsAChild(t *testing.T) {
	if args := os.Getenv(placedArgs); args != "" {
		readersAnchorctl = func(context.Context) (string, func(), error) {
			if os.Getenv(placedTemporary) != "" {
				return os.Getenv(placedStandIn), func() {}, nil
			}

			return os.Getenv(placedStandIn), nil, nil
		}

		os.Exit(Main(append([]string{"conflux"}, strings.Split(args, "\n")...)))
	}

	bin := filepath.Join(t.TempDir(), "anchorctl")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho $$ > \"$"+standInPID+"\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	for _, c := range []struct {
		args   []string
		socket string
	}{
		{[]string{"peers", "-socket", "unused"}, ""},
		{[]string{"peers"}, "unused"},
		{[]string{"peers", "-h"}, ""},
	} {
		for _, temporary := range []bool{false, true} {
			pidFile := filepath.Join(t.TempDir(), "pid")

			ctx, cancel := context.WithTimeout(t.Context(), childDeadline)

			conflux := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOnlyATemporaryCopyRunsAsAChild$") //nolint:gosec // this test binary
			conflux.Env = append(os.Environ(), placedArgs+"="+strings.Join(c.args, "\n"), placedStandIn+"="+bin,
				standInPID+"="+pidFile, anchorctl.SocketEnv+"="+c.socket)

			if temporary {
				conflux.Env = append(conflux.Env, placedTemporary+"=1")
			}

			out, err := conflux.CombinedOutput()

			cancel()

			b, _ := os.ReadFile(pidFile)
			pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))

			if err != nil || pid == 0 || (pid == conflux.Process.Pid) == temporary {
				t.Errorf("conflux %s with %s=%q, a temporary copy %v: ran anchorctl as pid %d, conflux being %d, want "+
					"it in conflux's place only where it is not a temporary copy (%v):\n%s", strings.Join(c.args, " "),
					anchorctl.SocketEnv, c.socket, temporary, pid, conflux.Process.Pid, err, out)
			}
		}
	}
}

// TestAnIgnoredSignalStaysIgnoredForItsAnchorctl: a conflux started ignoring SIGHUP, as nohup
// starts it, or SIGINT, as a shell starts what a script runs in the background, leaves it
// ignored for itself and for the anchorctl it runs, so the signal -- the terminal's, to the
// whole process group -- ends neither, as it would end neither had conflux replaced itself with
// anchorctl. What conflux is still sent is passed on.
func TestAnIgnoredSignalStaysIgnoredForItsAnchorctl(t *testing.T) {
	nohup, err := exec.LookPath("nohup")
	if err != nil {
		t.Fatal(err)
	}

	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		under []string
		sig   syscall.Signal
	}{
		{[]string{nohup}, syscall.SIGHUP},
		{[]string{sh, "-c", `trap '' INT; exec "$0" "$@"`}, syscall.SIGINT},
	} {
		t.Run(tc.sig.String(), func(t *testing.T) {
			dir, state := t.TempDir(), t.TempDir()
			pidFile, trapFile := filepath.Join(state, "pid"), filepath.Join(state, "trapped")

			argv := append(slices.Clone(tc.under), os.Args[0], "-test.run=^TestASignalToConfluxReachesItsAnchorctl$")

			conflux := exec.Command(argv[0], argv[1:]...) //nolint:gosec // this test binary
			conflux.Env = append(os.Environ(), standInDir+"="+dir, standInPID+"="+pidFile, standInTrap+"="+trapFile)
			conflux.Dir = state // where nohup would put nohup.out, had it a terminal to redirect

			// A process group of its own, which the signal goes to, as a terminal's does.
			conflux.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

			if err := conflux.Start(); err != nil {
				t.Fatal(err)
			}

			exited := make(chan error, 1)
			go func() { exited <- conflux.Wait() }()

			pid := waitForPID(t, pidFile, exited)

			t.Cleanup(func() {
				_ = syscall.Kill(pid, syscall.SIGKILL)
				_ = conflux.Process.Kill()
			})

			if err := syscall.Kill(-conflux.Process.Pid, tc.sig); err != nil {
				t.Fatal(err)
			}

			// Long enough for a signal that was not ignored to have ended the stand-in, whose trap
			// records it; then what ends conflux, which it passes on.
			time.Sleep(300 * time.Millisecond)

			if err := conflux.Process.Signal(syscall.SIGTERM); err != nil {
				t.Logf("conflux could not be sent SIGTERM: %v", err)
			}

			select {
			case <-exited:
			case <-time.After(10 * time.Second):
				t.Fatal("conflux was sent SIGTERM and had not ended 10s later")
			}

			if b, _ := os.ReadFile(trapFile); strings.TrimSpace(string(b)) != "TERM" {
				t.Errorf("the stand-in recorded %q, want TERM: the %v conflux was started ignoring reached it", b, tc.sig)
			}

			if code := conflux.ProcessState.ExitCode(); code != 7 {
				t.Errorf("conflux ended %v, want the stand-in's exit code, 7", conflux.ProcessState)
			}

			if left, _ := os.ReadDir(dir); len(left) > 0 {
				t.Errorf("conflux left its temporary anchorctl behind: %d entries in %s", len(left), dir)
			}
		})
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
				t.Fatalf("%v, %v second: the run was still going after %v:\n%s", tc.under, second, childDeadline, out)
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

// TestAFirstSignalStopsAnEphemeralRun: an interrupt, which Ctrl-C sends, or a SIGTERM, sent to an
// ephemeral run's conflux -- here while it enrols, with its anchord up -- ends Main's ctx, and the
// run with it, cleanly: conflux says it stopped and exits 0, the anchord it started is stopped and
// waited for, not left running, and the run's root is gone, with the .conflux it made in the
// CONFLUX_DIR, which is as it was.
func TestAFirstSignalStopsAnEphemeralRun(t *testing.T) {
	anchortest.Require(t)

	if os.Geteuid() == 0 {
		t.Skip("as root the run hands anchord to the conflux-ephemeral account, which it would make on this host")
	}

	defaultSignals(t)

	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGTERM} {
		t.Run(unix.SignalName(sig), func(t *testing.T) {
			// A short root rather than TempDir's: the run's control socket lies five levels below it.
			root := pathstest.ShortRoot(t)
			d := paths.EphemeralDirs(filepath.Join(root, paths.DirName, "ephemeral")) // paths.Ephemeral, under CONFLUX_DIR

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
			conflux.Env = append(os.Environ(), "CONFLUX_DIR="+root, childArgs+"="+strings.Join(args, "\n"))
			conflux.Stdout, conflux.Stderr = &out, &out

			if err := conflux.Start(); err != nil {
				t.Fatal(err)
			}

			exited := make(chan error, 1)
			go func() { exited <- conflux.Wait() }()

			// A test that fails kills conflux, then, once it has let go of the root's lock, stops the
			// anchord it recorded, which off Linux, with no parent-death signal, would run on past it.
			t.Cleanup(func() { daemon.Reap(d, 10*time.Second) })
			t.Cleanup(func() { _ = conflux.Process.Kill() })

			select {
			case c := <-enrolling:
				t.Cleanup(func() { _ = c.Close() })
			case err := <-exited:
				t.Fatalf("the run ended before it enrolled: %v\n%s", err, &out)
			case <-time.After(60 * time.Second):
				t.Fatal("the run had not enrolled 60s after it started")
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
			case <-time.After(30 * time.Second):
				t.Fatalf("the run was sent %v and had not ended 30s later", sig)
			}

			if code := conflux.ProcessState.ExitCode(); code != ExitOK || !strings.Contains(out.String(), "Stopped.") {
				t.Errorf("the run, sent %v, ended %v, want stopped and exit 0:\n%s", sig, conflux.ProcessState, &out)
			}

			if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
				t.Errorf("the run's anchord (pid %d) is still there after the run ended: %v", pid, err)

				_ = syscall.Kill(pid, syscall.SIGKILL)
			}

			if _, err := os.Lstat(d.State); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("the run's root %s is still there after it ended: %v", d.State, err)
			}

			if left, err := os.ReadDir(root); err != nil || len(left) > 0 {
				t.Errorf("the CONFLUX_DIR %s, empty before the run, holds %v after it ended (%v)", root, left, err)
			}
		})
	}
}

// TestCtrlCEndsARemakeWaitingOnAnExtraction: register -- tidy, which an update has the new conflux run --
// holds the supervisor's lock while it empties bin/ under bin's lock (libexec.Remake), which an extraction
// in progress holds, as one stopped where it stands holds it for good: here the test holds it. register
// waits, saying after a second that it waits for another conflux extracting there, and Ctrl+C -- SIGINT,
// to conflux, run in this process -- ends the wait and the command: exit 1, the supervisor's lock let go
// of, and nothing registered or started.
func TestCtrlCEndsARemakeWaitingOnAnExtraction(t *testing.T) {
	anchortest.Require(t)
	rootOnLinux(t)
	defaultSignals(t) // Main catches SIGINT whatever this test binary was started ignoring

	d := pathstest.Dirs(t)
	mgr := &fakeManager{d: d}
	standInService(t, mgr)

	unlock, err := flock.Acquire(filepath.Join(d.Libexec(), ".lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()

	said := &lockedBuffer{}

	oldOut, oldErr := ui.Out, ui.Errw
	ui.Out, ui.Errw = io.Discard, said

	t.Cleanup(func() { ui.Out, ui.Errw = oldOut, oldErr })

	returned := make(chan int, 1)
	go func() { returned <- Main([]string{"conflux", "register"}) }()

	waiting := "waiting for another conflux extracting in " + d.Libexec()

	deadline := time.Now().Add(10 * time.Second)

	for ; !strings.Contains(said.String(), waiting); time.Sleep(10 * time.Millisecond) {
		select {
		case code := <-returned:
			t.Fatalf("register ended %d before it said it waited for the extraction:\n%s", code, said)
		default:
		}

		if time.Now().After(deadline) {
			t.Fatalf("register had not said %q 10s after it started:\n%s", waiting, said)
		}
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGINT); err != nil {
		t.Fatal(err)
	}

	select {
	case code := <-returned:
		if code == ExitOK {
			t.Errorf("register, interrupted waiting for the extraction, exited 0:\n%s", said)
		}
	case <-time.After(childDeadline):
		t.Fatalf("register was sent SIGINT and had not returned %v later:\n%s", childDeadline, said)
	}

	release, ok, err := flock.TryAcquire(d.ServeLockFile())
	if err != nil || !ok {
		t.Errorf("register, interrupted, kept the supervisor's lock %s (%v)", d.ServeLockFile(), err)
	} else {
		release()
	}

	if len(mgr.installs) > 0 || mgr.restarts > 0 {
		t.Errorf("register, interrupted, registered %q and restarted the service %d times", mgr.installs, mgr.restarts)
	}
}

// lockedBuffer is a bytes.Buffer that conflux, running on a goroutine of its own, writes while the test
// reads it.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()

	return l.b.String()
}

// defaultSignals starts the children of the rest of the test with SIGHUP and SIGINT at their
// defaults, whatever this test binary was started ignoring -- under nohup, or in a script's
// background -- which they would otherwise inherit, and a test of a signal's default would then
// see the ignore. Notify puts a handler in the ignore's place, and exec leaves no handler
// standing; Stop puts the ignore back.
func defaultSignals(t *testing.T) {
	t.Helper()

	sigs := make(chan os.Signal, 2)
	signal.Notify(sigs, syscall.SIGHUP, syscall.SIGINT)

	t.Cleanup(func() { signal.Stop(sigs) })
}

// waitForPID is the stand-in's PID once it has started, which is once conflux is waiting on it.
func waitForPID(t *testing.T, path string, exited <-chan error) int {
	t.Helper()

	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		select {
		case err := <-exited:
			t.Fatalf("conflux ended before its anchorctl started: %v", err)
		default:
		}

		if b, err := os.ReadFile(path); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
				return pid
			}
		}
	}

	t.Fatal("the stand-in anchorctl never started")

	return 0
}

// trapName is a signal's name as the shell's trap spells it, TERM for syscall.SIGTERM.
func trapName(s syscall.Signal) string { return strings.TrimPrefix(unix.SignalName(s), "SIG") }
