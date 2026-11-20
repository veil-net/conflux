//go:build !windows

package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/paths"
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
// which signal it was sent, exiting 7.
const standIn = `#!/bin/sh
if [ -n "$` + standInTrap + `" ]; then
	for s in TERM HUP INT; do
		trap "echo $s > \"\$` + standInTrap + `\"; exit 7" $s
	done
fi
echo $$ > "$` + standInPID + `.tmp" && mv "$` + standInPID + `.tmp" "$` + standInPID + `"
while :; do sleep 0.05; done
`

// TestASignalToConfluxReachesItsAnchorctl: the anchorctl conflux runs as a child, for usage or
// a socket the user named, is sent what conflux's PID alone is sent -- a kill, a service
// manager's stop, a hangup -- as it would be had conflux replaced itself with it. conflux ends
// as anchorctl ends, by its exit code or by the signal, and its temporary copy goes with it.
func TestASignalToConfluxReachesItsAnchorctl(t *testing.T) {
	if dir := os.Getenv(standInDir); dir != "" {
		detachedAnchorctl = func(paths.Dirs) (string, func(), error) {
			tmp, err := os.MkdirTemp(dir, "conflux-usage-")
			if err != nil {
				return "", nil, err
			}

			bin := filepath.Join(tmp, "anchorctl")

			return bin, func() { _ = os.RemoveAll(tmp) }, os.WriteFile(bin, []byte(standIn), 0o700)
		}

		os.Exit(Main([]string{"conflux", "peers", "-socket", "unused"}))
	}

	for _, tc := range []struct {
		sig  syscall.Signal
		trap bool
	}{
		{syscall.SIGTERM, true},
		{syscall.SIGHUP, true},
		{syscall.SIGINT, true},
		{syscall.SIGTERM, false},
	} {
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
				if b, _ := os.ReadFile(trapFile); strings.TrimSpace(string(b)) != strings.TrimPrefix(signalName(tc.sig), "SIG") {
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

// TestNohupStillHoldsForItsAnchorctl: a conflux started ignoring SIGHUP, as nohup starts it,
// leaves it ignored for itself and for the anchorctl it runs, so a hangup -- the terminal's,
// to the whole process group -- ends neither, as it would end neither had conflux replaced
// itself with anchorctl. What conflux is still sent is passed on.
func TestNohupStillHoldsForItsAnchorctl(t *testing.T) {
	nohup, err := exec.LookPath("nohup")
	if err != nil {
		t.Fatal(err)
	}

	dir, state := t.TempDir(), t.TempDir()
	pidFile, trapFile := filepath.Join(state, "pid"), filepath.Join(state, "trapped")

	conflux := exec.Command(nohup, os.Args[0], "-test.run=^TestASignalToConfluxReachesItsAnchorctl$") //nolint:gosec // this test binary
	conflux.Env = append(os.Environ(), standInDir+"="+dir, standInPID+"="+pidFile, standInTrap+"="+trapFile)
	conflux.Dir = state // where nohup would put nohup.out, had it a terminal to redirect

	// A process group of its own, which the hangup goes to, as a terminal's does.
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

	if err := syscall.Kill(-conflux.Process.Pid, syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}

	// Long enough for a hangup that was not ignored to have ended the stand-in, whose trap
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
		t.Errorf("the stand-in recorded %q, want TERM: the hangup nohup holds off reached it", b)
	}

	if code := conflux.ProcessState.ExitCode(); code != 7 {
		t.Errorf("conflux ended %v, want the stand-in's exit code, 7", conflux.ProcessState)
	}

	if left, _ := os.ReadDir(dir); len(left) > 0 {
		t.Errorf("conflux left its temporary anchorctl behind: %d entries in %s", len(left), dir)
	}
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

// signalName is a signal's name as the shell's trap spells it, SIGTERM for syscall.SIGTERM.
func signalName(s syscall.Signal) string {
	return map[syscall.Signal]string{syscall.SIGTERM: "SIGTERM", syscall.SIGHUP: "SIGHUP", syscall.SIGINT: "SIGINT"}[s]
}
