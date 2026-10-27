package daemon

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/veil-net/conflux/internal/flock"
	"github.com/veil-net/conflux/internal/paths"
)

// orphan starts the stand-in anchord as a supervisor would have, records it, and waits on
// it in the background as init would for a process whose supervisor has died: without
// the wait the test, its real parent, keeps it a zombie that still answers to its pid.
func orphan(t *testing.T, d paths.Dirs, mode, exe string) (*exec.Cmd, <-chan struct{}) {
	t.Helper()
	t.Setenv(fakeAnchordEnv, mode)
	t.Setenv("GORACE", "atexit_sleep_ms=0")

	cmd := exec.Command(os.Args[0], "-socket", d.Socket())
	cmd.SysProcAttr = procAttr()

	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	// Listening before anything signals it: a signal that arrives before the handler is
	// installed is the default one.
	if mode == "serve" {
		buf := make([]byte, 64)
		if n, _ := out.Read(buf); !strings.Contains(string(buf[:n]), "anchord listening") {
			t.Fatalf("the stand-in anchord said %q", buf[:n])
		}
	}

	exited := make(chan struct{})

	go func() {
		_ = cmd.Wait()
		close(exited)
	}()

	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-exited
	})

	if err := recordDaemon(d, cmd.Process.Pid, exe); err != nil {
		t.Fatal(err)
	}

	return cmd, exited
}

func gone(t *testing.T, exited <-chan struct{}) bool {
	t.Helper()

	select {
	case <-exited:
		return true
	case <-time.After(5 * time.Second):
		return false
	}
}

func recordGone(t *testing.T, d paths.Dirs) {
	t.Helper()

	if _, err := os.Stat(d.DaemonPIDFile()); !os.IsNotExist(err) {
		t.Errorf("the pid record is still there after the reap (%v)", err)
	}
}

// TestSpawnRecordsTheDaemon: the record names the anchord the supervisor started for as
// long as it runs, and is gone once it has been waited for.
func TestSpawnRecordsTheDaemon(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a console control event needs the console this test shares")
	}

	s, _ := supervised(t, "serve")

	_, c, err := s.spawn(t.Context())
	if err != nil {
		t.Fatalf("spawn: %v", err)
	}

	pid, exe, ok := recorded(s.Dirs)
	if !ok || pid != c.cmd.Process.Pid || exe != os.Args[0] {
		t.Errorf("the record says pid %d, %q (ok %v); want %d, %q", pid, exe, ok, c.cmd.Process.Pid, os.Args[0])
	}

	for deadline := time.Now().Add(5 * time.Second); !strings.Contains(s.tail.String(), "anchord listening"); {
		if time.Now().After(deadline) {
			t.Fatalf("the stand-in anchord never said it was listening:\n%s", s.tail)
		}

		time.Sleep(5 * time.Millisecond)
	}

	returns(t, "shutdown", func() { s.shutdown(c) })
	recordGone(t, s.Dirs)
}

// TestReapStopsAnOrphanedDaemon: the anchord a supervisor that died left running is
// stopped by the next one, and its socket file goes with it.
func TestReapStopsAnOrphanedDaemon(t *testing.T) {
	d := dirs(t)
	cmd, exited := orphan(t, d, "serve", os.Args[0])

	if err := os.WriteFile(d.Socket(), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	pid, err := ReapOrphan(d)
	if err != nil || pid != cmd.Process.Pid {
		t.Fatalf("ReapOrphan = %d, %v; want %d", pid, err, cmd.Process.Pid)
	}

	if !gone(t, exited) {
		t.Fatal("the orphaned anchord is still running")
	}

	if _, err := os.Stat(d.Socket()); !os.IsNotExist(err) {
		t.Errorf("the dead daemon's socket file is still there (%v)", err)
	}

	recordGone(t, d)
}

// TestReapSparesAProcessThatIsNotTheRecordedDaemon: a pid is only a number, and a process
// running another executable than the one recorded is somebody else's.
func TestReapSparesAProcessThatIsNotTheRecordedDaemon(t *testing.T) {
	d := dirs(t)

	other := filepath.Join(t.TempDir(), "not-anchord")
	if err := os.WriteFile(other, nil, 0o700); err != nil {
		t.Fatal(err)
	}

	_, exited := orphan(t, d, "serve", other)

	if pid, err := ReapOrphan(d); pid != 0 || err != nil {
		t.Fatalf("ReapOrphan = %d, %v; want nothing stopped", pid, err)
	}

	select {
	case <-exited:
		t.Fatal("a process running another executable was stopped")
	case <-time.After(200 * time.Millisecond):
	}

	recordGone(t, d)
}

// TestReapForgetsADaemonThatHasGone: a record naming a process that has exited is
// cleared, and nothing is signalled.
func TestReapForgetsADaemonThatHasGone(t *testing.T) {
	d := dirs(t)
	_, exited := orphan(t, d, "1", os.Args[0])

	if !gone(t, exited) {
		t.Fatal("the stand-in that exits at once did not")
	}

	if pid, err := ReapOrphan(d); pid != 0 || err != nil {
		t.Errorf("ReapOrphan = %d, %v for a daemon that had gone", pid, err)
	}

	recordGone(t, d)
}

// TestReapWithoutAnExePathNeedsTheSocketLock: where the system names no executable, the
// recorded pid is taken for anchord only while something holds anchor's lock on this
// root's socket, as a daemon serving it does.
func TestReapWithoutAnExePathNeedsTheSocketLock(t *testing.T) {
	defer func(was func(int) (string, error)) { exeOf = was }(exeOf)
	exeOf = func(int) (string, error) { return "", errNoExePath }

	d := dirs(t)
	_, spared := orphan(t, d, "serve", os.Args[0])

	if pid, err := ReapOrphan(d); pid != 0 || err != nil {
		t.Fatalf("ReapOrphan = %d, %v with the socket's lock free; want nothing stopped", pid, err)
	}

	select {
	case <-spared:
		t.Fatal("a process nothing showed to be anchord was stopped")
	case <-time.After(200 * time.Millisecond):
	}

	cmd, exited := orphan(t, d, "serve", os.Args[0])

	unlock, err := flock.Acquire(d.Socket() + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()

	if pid, err := ReapOrphan(d); pid != cmd.Process.Pid || err != nil {
		t.Fatalf("ReapOrphan = %d, %v with the socket's lock held; want %d", pid, err, cmd.Process.Pid)
	}

	if !gone(t, exited) {
		t.Fatal("the daemon holding the socket's lock is still running")
	}
}

// TestReapAfterAnUpgradeKnowsTheOldSocketLock: the first supervisor after an upgrade from
// 1.0.0 finds that release's daemon holding the lock at the socket's old path, where a
// system that names no executable can tell it by nothing else.
func TestReapAfterAnUpgradeKnowsTheOldSocketLock(t *testing.T) {
	defer func(was func(int) (string, error)) { exeOf = was }(exeOf)
	exeOf = func(int) (string, error) { return "", errNoExePath }

	d := dirs(t)
	cmd, exited := orphan(t, d, "serve", os.Args[0])

	unlock, err := flock.Acquire(d.LegacySocket() + ".lock")
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()

	if pid, err := ReapOrphan(d); pid != cmd.Process.Pid || err != nil {
		t.Fatalf("ReapOrphan = %d, %v with the old socket's lock held; want %d", pid, err, cmd.Process.Pid)
	}

	if !gone(t, exited) {
		t.Fatal("the 1.0.0 daemon is still running")
	}
}

// TestASecondSupervisorIsRefused: one supervisor per root, since each stops the anchord
// the last one left and two would stop each other's.
func TestASecondSupervisorIsRefused(t *testing.T) {
	d := dirs(t)

	unlock, err := flock.Acquire(d.ServeLockFile())
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()

	err = (&Supervisor{Dirs: d}).Run(t.Context())
	if err == nil || !strings.Contains(err.Error(), "already serving") {
		t.Fatalf("Run with the root's serve lock held = %v, want a refusal", err)
	}
}

// TestTheRecordSurvivesOnlyWhatItNames: a record that does not parse is dropped, not
// acted on.
func TestTheRecordSurvivesOnlyWhatItNames(t *testing.T) {
	d := dirs(t)

	for _, body := range []string{"", "x\n/bin/anchord\n", "12\n", "-3\n/bin/anchord\n", "0\n/bin/anchord\n"} {
		if err := os.WriteFile(d.DaemonPIDFile(), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}

		if _, _, ok := recorded(d); ok {
			t.Errorf("the record %q was read as a daemon", body)
		}
	}

	if err := os.WriteFile(d.DaemonPIDFile(), []byte(strconv.Itoa(4242)+"\n/x/anchord\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if pid, exe, ok := recorded(d); !ok || pid != 4242 || exe != "/x/anchord" {
		t.Errorf("recorded() = %d, %q, %v", pid, exe, ok)
	}
}
