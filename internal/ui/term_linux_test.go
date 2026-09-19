//go:build linux

package ui

import (
	"fmt"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

// TestIsTerminalAcceptsATerminal is the other half of the check, and the one that
// matters most: a test that is only ever stricter would pass with the prompt gone
// entirely. Linux only, because opening a pty by hand is.
func TestIsTerminalAcceptsATerminal(t *testing.T) {
	hush(t)

	pts := openPTY(t)
	SetIn(pts)

	if !IsTerminal() {
		t.Error("IsTerminal() on a pty = false, want true: nobody can be prompted any more")
	}
}

// openPTY opens one end of a pseudo-terminal, or skips: a container without
// /dev/ptmx has nothing to test against and no bug to report either.
func openPTY(t *testing.T) *os.File {
	t.Helper()

	ptmx, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		t.Skipf("no pty available: %v", err)
	}

	t.Cleanup(func() { ptmx.Close() })

	if err := unix.IoctlSetPointerInt(int(ptmx.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		t.Skipf("could not unlock the pty: %v", err)
	}

	n, err := unix.IoctlGetInt(int(ptmx.Fd()), unix.TIOCGPTN)
	if err != nil {
		t.Skipf("could not name the pty: %v", err)
	}

	// O_NOCTTY: this is a test reading a descriptor, not a session taking a
	// controlling terminal.
	pts, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		t.Skipf("could not open the pty: %v", err)
	}

	t.Cleanup(func() { pts.Close() })

	return pts
}
