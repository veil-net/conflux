package cli

import (
	"bytes"
	"errors"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/daemon"
	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/pathstest"
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
