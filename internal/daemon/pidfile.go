package daemon

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/veil-net/conflux/internal/config"
	"github.com/veil-net/conflux/internal/flock"
	"github.com/veil-net/conflux/internal/paths"
)

// The anchord a supervisor started, written down so that whatever follows a supervisor
// that died without stopping it can.
//
// A supervisor that ends normally stops its anchord on the way out. One that is killed
// does not, and on every platform but systemd -- which kills the unit's whole cgroup --
// that anchord runs on: launchd ends the job's process group and anchord has its own,
// and rc and the Windows SCM end only the process they started. It keeps the socket, and
// anchor's lock on it, so the next supervisor's anchord is refused as "already served by a
// running daemon" for as long as it lives, and a node nobody can reach goes on running
// beside a service retrying for ever. anchord has no RPC that ends the daemon itself, so
// the one way to stop it is by its pid.

// errNoExePath is a platform that does not say which executable a process runs.
var errNoExePath = errors.New("this system does not report a process's executable")

// exeOf is processExe, as a variable so a test can be a system that reports none.
var exeOf = processExe

// recordDaemon writes down the anchord just started: its pid, and the executable it runs.
func recordDaemon(d paths.Dirs, pid int, exe string) error {
	return config.WriteFileAtomic(d.DaemonPIDFile(), []byte(strconv.Itoa(pid)+"\n"+exe+"\n"), 0o600)
}

// forgetDaemon removes the record, once the anchord it names has been waited for.
func forgetDaemon(d paths.Dirs) { _ = os.Remove(d.DaemonPIDFile()) }

func recorded(d paths.Dirs) (pid int, exe string, ok bool) {
	b, err := os.ReadFile(d.DaemonPIDFile())
	if err != nil {
		return 0, "", false
	}

	line, exe, ok := strings.Cut(strings.TrimSuffix(string(b), "\n"), "\n")

	pid, err = strconv.Atoi(line)
	if !ok || err != nil || pid <= 0 || exe == "" {
		return 0, "", false
	}

	return pid, exe, true
}

// ReapOrphan stops the anchord a previous supervisor of this root left running, if it did,
// and reports its pid.
//
// The caller holds the root's serve lock, so no live supervisor's daemon can be the one
// recorded. A pid is only a number, though, and may have been given to anything since: it
// is taken for anchord only when the process runs the executable recorded beside it, or --
// on a system that reports no executable -- when something holds anchor's lock on this
// root's socket, which only a daemon serving it does.
func ReapOrphan(d paths.Dirs) (int, error) {
	pid, exe, ok := recorded(d)

	defer forgetDaemon(d)

	if !ok || !alive(pid) || !isOurDaemon(d, pid, exe) {
		return 0, nil
	}

	if err := stopOrphan(pid); err != nil {
		return pid, fmt.Errorf("stop the anchord left running as pid %d: %w", pid, err)
	}

	// A killed daemon leaves its socket file, which status and pass-through read as one
	// that is running. Never the .lock beside it: anchor keeps that file for good.
	_ = os.Remove(d.Socket())

	return pid, nil
}

// Reap is ReapOrphan for `conflux uninstall`, once the boot service is removed: it waits
// for the service's own supervisor to let go of the root, then stops whatever anchord is
// still recorded, so nothing is left running out of a directory about to be deleted.
func Reap(d paths.Dirs, wait time.Duration) {
	if _, err := os.Stat(d.DaemonPIDFile()); err != nil {
		return
	}

	for deadline := time.Now().Add(wait); ; time.Sleep(100 * time.Millisecond) {
		unlock, ok, err := flock.TryAcquire(d.ServeLockFile())
		if err != nil {
			return
		}

		if ok {
			defer unlock()

			break
		}

		if time.Now().After(deadline) {
			return
		}
	}

	_, _ = ReapOrphan(d)
}

func isOurDaemon(d paths.Dirs, pid int, exe string) bool {
	if reported, err := exeOf(pid); err == nil {
		if match, known := sameExe(reported, exe); known {
			return match
		}
	}

	return socketHeld(d)
}

// socketHeld reports whether something holds anchor's lock on this root's socket, where a
// daemon serving it always does: at its own path, or, the first time a supervisor runs
// after an upgrade, at the path conflux 1.0.0 used.
//
// Asked through flock.Held, never by taking the lock the way the supervisor's own locks
// are: the lock lives in anchord's run directory, which belongs to whoever anchord ran as,
// and opening it to create would let that account point root at any file.
func socketHeld(d paths.Dirs) bool {
	for _, lock := range []string{d.Socket() + ".lock", d.LegacySocket() + ".lock"} {
		if held, err := flock.Held(lock); err == nil && held {
			return true
		}
	}

	return false
}

// sameExe compares the executable a process runs with the one recorded for it: the same
// path, or two paths to one file. known is false when neither can be shown -- a path that
// no longer exists, spelled differently from the record.
func sameExe(reported, recorded string) (match, known bool) {
	if reported == recorded {
		return true, true
	}

	a, errA := os.Stat(reported)
	b, errB := os.Stat(recorded)

	if errA != nil || errB != nil {
		return false, false
	}

	return os.SameFile(a, b), true
}
