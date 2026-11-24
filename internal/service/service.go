// Package service registers conflux with the platform's boot manager: systemd,
// launchd, rc on the BSDs, or the Windows service control manager.
//
// One rule shapes the whole interface: Install registers and does not start. That is
// what lets `conflux install` put the service in place on a machine that has no
// configuration yet, so that a later `up` has somewhere to land.
package service

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/update"
)

// Manager is one platform's boot manager.
type Manager interface {
	// Install registers the service to start at boot. Idempotent, and it does not
	// start anything.
	Install(exe string, args ...string) error

	// Remove deregisters it and deletes what registering it wrote; what the service wrote to
	// the system's log stays, the system's.
	// Each step tolerates its own failure, so a half-removed service can always be
	// finished off.
	Remove() error

	Stop() error

	// Restart is an operator's start -- `up`, `proxy`, `start` -- and nothing else calls it,
	// so it starts a service the manager had given up on as well.
	Restart() error

	// Reconcile is Install as the running service does it at every start: the registration
	// put back to what this conflux writes where it was changed, with nothing loaded,
	// stopped or restarted, since what calls it is the service itself.
	Reconcile(exe string, args ...string) error

	Installed() (bool, error)

	// Describe is one line for `conflux status`.
	Describe() string

	// LogHint says where the service's output is, as something to run or open.
	LogHint() string
}

// openFiles is the open-file limit the service is given, where conflux sets one: systemd's
// LimitNOFILE, and OpenBSD's login class.
const openFiles = 1048576

// New returns this platform's manager.
func New() Manager { return newManager() }

// Place copies this conflux to where the boot service runs it from, and returns that
// path.
//
// The service runs as root (SYSTEM on Windows) and starts whatever file it names at every
// boot, so that file must be one only root can change. Wherever conflux was run from --
// a home directory, a download, C:\tools -- may be writable by somebody else, who could
// then swap it for their own program and have it run as root at the next start. So the
// service runs a copy in conflux's root, which only root can write and `uninstall`
// removes, and each `up`, `proxy`, `install`, `start` and `update` refreshes it: an
// upgraded conflux reaches the service the next time one of them runs.
//
// The copy is written beside its destination and renamed over it, so a service running
// the old one keeps it. Windows will not replace the image of a running process but will
// rename it, so there the old copy is moved aside first and removed by a later Place.
func Place(d paths.Dirs) (string, error) {
	src, err := Executable()
	if err != nil {
		return "", err
	}

	return PlaceFrom(d, src)
}

// PlaceFrom is Place with the file to copy named, rather than this process's own. `conflux
// update` uses it once it has replaced the file it was started from: what this process
// reports as its executable after that is not something every platform agrees on.
func PlaceFrom(d paths.Dirs, src string) (string, error) {
	dst := d.ServiceExecutable()

	// The copy a service ran until the last Place, which Windows had moved aside; one still
	// running is fine.
	_ = os.Remove(dst + ".old")

	if src == dst || sameFile(src, dst) {
		return dst, nil
	}

	if err := copyExecutable(src, dst); err != nil {
		return "", fmt.Errorf("place this conflux at %s for the boot service: %w", dst, err)
	}

	return dst, nil
}

// Executable is the file this process runs, symlinks followed: the file a copy is made of,
// and the one uninstall on Windows asks whether it is the installed conflux.
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

// StagedPrefix begins the name of the file the service's copy of conflux is written to beside
// it, before it is renamed into place: what the supervisor's tidy spares while it is young
// enough to be a copy in progress.
const StagedPrefix = ".conflux-"

// copyExecutable writes src to dst through a file beside it, renamed into place.
func copyExecutable(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	tmp, err := os.CreateTemp(filepath.Dir(dst), StagedPrefix+"*")
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

	// Renamed into place, or on Windows, over the running service's image, which is moved
	// aside first, to dst.old; the old copy is put back if the new one cannot go in.
	return update.Replace(tmp.Name(), dst)
}
