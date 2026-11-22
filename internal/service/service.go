// Package service registers conflux with the platform's boot manager: systemd,
// launchd, rc on the BSDs, or the Windows service control manager.
//
// One rule shapes the whole interface: Install registers, and starts nothing that is not
// running. That is what lets `conflux install` put the service in place on a machine that
// has no configuration yet, so that a later `up` has somewhere to land.
package service

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/update"
)

// The supervisor's two exits a restart would only repeat, which no boot manager restarts
// it after: systemd's unit names them in RestartPreventExitStatus, launchd is told 0 in
// their place, and the SCM a clean stop.
const (
	// ExitNoConfig means this machine has never been configured: there is nothing to
	// start. EX_CONFIG.
	ExitNoConfig = 78

	// ExitChildFailed means a configuration conflux or anchor refuses for good, or a host
	// no retry changes: no restart would start it.
	ExitChildFailed = 70
)

// Manager is one platform's boot manager.
type Manager interface {
	// Install registers the service to start at boot. Idempotent, and it starts nothing that
	// is not running and leaves nothing stopped that is. A definition already as it would
	// write it is left as it is. launchd's, whose loaded job runs from the definition it was
	// loaded with, unloads a stopped job whose definition changed and loads a running one
	// again, which restarts it on the new one; the Restart that follows from the same manager
	// then starts nothing.
	Install(exe string, args ...string) error

	// Remove deregisters it and deletes what registering it wrote, its log included.
	// Each step tolerates its own failure, so a half-removed service can always be
	// finished off.
	Remove() error

	Stop() error

	// Running reports whether the service manager says the service runs: its process started, or
	// starting, and not yet stopped; or why it could not ask. tidy asks it before it stops the service
	// for an update, so that what it starts again after is only what it stopped. launchd's print and
	// rc's status and check answer "not running" by their exit, so only systemd's and the SCM's
	// questions can go unanswered.
	Running() (bool, error)

	// Restart is an operator's start -- `up`, `proxy`, `start` -- and nothing else calls it,
	// so it starts a service the manager had given up on as well.
	Restart() error

	Installed() (bool, error)

	// Describe is one line for `conflux status`.
	Describe() string

	// LogHint says where the service's output is, as something to run or open.
	LogHint() string
}

// New returns this platform's manager: the same one for the life of the process, so the
// Restart that follows an Install knows what the Install did, whichever caller asked for
// each. Only launchd's has anything to know (launchdManager).
func New() Manager { return manager() }

var manager = sync.OnceValue(newManager)

// PlaceAfresh copies this conflux to where the boot service runs it from, and returns that
// path: the copy written again whatever it holds, so that no file an earlier conflux made there,
// nor a handle anybody opened on one, outlives the copy, and what a copy that never went in place
// left beside it goes first. Where Placed finds the copy is this conflux already, it is kept
// instead (Keep).
//
// The service runs as root (SYSTEM on Windows) and starts whatever file it names at every
// boot, so that file must be one only root can change. Wherever conflux was run from --
// a home directory, a download, C:\tools -- may be writable by somebody else, who could
// then swap it for their own program and have it run as root at the next start. So the
// service runs a copy in the state directory, which only root can write and `uninstall`
// removes, and each `up`, `proxy`, `observe`, `enrol`, `install`, `start` and `update` refreshes
// it: an upgraded conflux reaches the service the next time one of them runs.
//
// The copy is written beside its destination and renamed over it, so a service running
// the old one keeps it. Windows will not replace the image of a running process but will
// rename it, so there the old copy is moved aside first and removed by the next PlaceAfresh or
// Keep.
func PlaceAfresh(d paths.Dirs) (string, error) {
	src, err := Executable()
	if err != nil {
		return "", err
	}

	dst := d.ServiceExecutable()
	removeBeside(dst, true)

	if err := copyExecutable(src, dst); err != nil {
		return "", fmt.Errorf("place this conflux at %s for the boot service: %w", dst, err)
	}

	return dst, nil
}

// OwnCopy makes the copy of conflux the boot service runs one of conflux's own before the service starts
// on it: kept where it is as conflux makes a file of its own (paths.Dirs.Ours), and otherwise -- not
// there, or not as conflux makes it, as an earlier conflux left one an administrator's on a Windows
// client, whose processes that are not elevated could change it for the next start to run as SYSTEM --
// this conflux placed afresh (PlaceAfresh). The caller has made d's roots (EnsureServing), or held them
// to the readers' check, first. The supervisor runs it from the copy itself as it starts, which keeps the
// image it runs: the copy is written beside it and renamed over it, and on Windows, which will not
// replace a running image, that is moved aside first.
func OwnCopy(d paths.Dirs) error {
	if d.Ours(d.ServiceExecutable()) == nil {
		return nil
	}

	_, err := PlaceAfresh(d)

	return err
}

// Placed reports whether the copy the boot service runs is this conflux, byte for byte: what every
// re-run of the same conflux finds, and an update, or a newer conflux put in place by hand, does
// not.
func Placed(d paths.Dirs) bool {
	src, err := Executable()

	return err == nil && sameFile(src, d.ServiceExecutable())
}

// Keep is PlaceAfresh for a copy Placed has just found to be this conflux, which it does not compare
// again or write: it removes the copy a service ran until the last PlaceAfresh, which only Windows
// moves aside (removeBeside), and returns the copy's path.
func Keep(d paths.Dirs) string {
	dst := d.ServiceExecutable()
	removeBeside(dst, false)

	return dst
}

// removeBeside removes what an earlier copy left beside dst, the copy the service runs: the copy a
// service ran until the last PlaceAfresh, which only Windows moves aside, still running being fine;
// and, afresh, as PlaceAfresh writes the copy, that too whatever the platform, and what a copy that
// never went in place left, copyExecutable's file beside it, which its own removal missed in a crash
// (paths.RemovePrefixed).
func removeBeside(dst string, afresh bool) {
	if runtime.GOOS == "windows" || afresh {
		_ = os.Remove(dst + ".old")
	}

	if afresh {
		paths.RemovePrefixed(filepath.Dir(dst), copyPrefix, os.Remove)
	}
}

// Executable is the file this process runs, symlinks followed: the file PlaceAfresh copies,
// and the one `conflux update` replaces, rather than the link somebody put on their PATH.
func Executable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("find this executable: %w", err)
	}

	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}

	return filepath.Clean(exe), nil
}

// sameFile reports whether b already holds a's bytes, which every re-run of `up` with
// the same conflux finds.
func sameFile(a, b string) bool {
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}

	bi, err := os.Stat(b)
	if err != nil || ai.Size() != bi.Size() {
		return false
	}

	if os.SameFile(ai, bi) {
		return true
	}

	fa, err := os.Open(a)
	if err != nil {
		return false
	}
	defer fa.Close()

	fb, err := os.Open(b)
	if err != nil {
		return false
	}
	defer fb.Close()

	bufA, bufB := make([]byte, 1<<20), make([]byte, 1<<20)

	for {
		n, errA := io.ReadFull(fa, bufA)
		m, errB := io.ReadFull(fb, bufB)

		if n != m || !bytes.Equal(bufA[:n], bufB[:m]) {
			return false
		}

		if errA != nil || errB != nil {
			return errors.Is(errA, io.ErrUnexpectedEOF) || errors.Is(errA, io.EOF)
		}
	}
}

// copyPrefix begins the name of the file copyExecutable writes beside the copy before it renames it
// into place.
const copyPrefix = ".conflux-"

// copyExecutable writes src to dst through a file beside it, renamed into place.
func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp, err := os.CreateTemp(filepath.Dir(dst), copyPrefix+"*")
	if err != nil {
		return err
	}

	defer os.Remove(tmp.Name()) // nothing once it has been renamed

	if _, err := io.Copy(tmp, in); err != nil {
		tmp.Close()

		return err
	}

	if err := tmp.Chmod(0o700); err != nil {
		tmp.Close()

		return err
	}

	if err := tmp.Sync(); err != nil {
		tmp.Close()

		return err
	}

	if err := tmp.Close(); err != nil {
		return err
	}

	// Over a running service's image too: update.Replace moves that aside on Windows.
	return update.Replace(tmp.Name(), dst)
}
