package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/paths"
)

// TestAKilledEphemeralRunTakesItsDaemonWithIt: an ephemeral run that is killed outright,
// with no chance to stop anything, still takes its anchord with it: the parent-death signal
// its anchord was started with ends it, and nothing is left running with the credential in
// memory.
func TestAKilledEphemeralRunTakesItsDaemonWithIt(t *testing.T) {
	is := newIssuer(t)

	t.Setenv(fakeAnchordEnv, "serve")
	t.Setenv(fakeAnchordListenEnv, "1")
	t.Setenv(fakeAnchorctlStatusEnv, "running")
	fakeCtl(t)

	root := filepath.Join(dirs(t).State, "e")

	runner := exec.Command(os.Args[0], ephemeralRunnerArg, root) //nolint:gosec // this test binary
	runner.Env = append(os.Environ(),
		ephemeralRunnerManifest+"="+string(handed(t, is, time.Now().Add(-time.Hour), time.Now().Add(30*24*time.Hour))),
		ephemeralRunnerAPI+"="+is.srv.URL)

	if err := runner.Start(); err != nil {
		t.Fatal(err)
	}

	var pid int

	eventually(t, "the run's anchord to be recorded", func() bool {
		b, err := os.ReadFile(paths.EphemeralDirs(root).DaemonPIDFile())
		if err != nil {
			return false
		}

		pid, err = strconv.Atoi(strings.SplitN(string(b), "\n", 2)[0])

		return err == nil && running(pid)
	})

	if err := runner.Process.Kill(); err != nil {
		t.Fatal(err)
	}

	_ = runner.Wait()

	eventually(t, "the run's anchord to end with it", func() bool { return !running(pid) })
}

// running reports whether pid is a process that has not ended: one that is gone, or a zombie
// nothing has reaped yet, has.
func running(pid int) bool {
	b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return false
	}

	// The state follows the command name, which is in parentheses and may hold anything.
	s := string(b)
	if i := strings.LastIndexByte(s, ')'); i >= 0 && i+2 < len(s) {
		return s[i+2] != 'Z' && s[i+2] != 'X'
	}

	return true
}
