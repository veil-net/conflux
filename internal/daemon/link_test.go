package daemon

import (
	"path/filepath"
	"testing"
	"time"
)

func TestDevicePath(t *testing.T) {
	for spec, want := range map[string]string{
		"/dev/ttyUSB0":        "/dev/ttyUSB0",
		"/dev/ttyUSB0:115200": "/dev/ttyUSB0",
		"/dev/ttyS1:57600":    "/dev/ttyS1",

		// fd:N adopts a descriptor and opens nothing, so there is no path to watch.
		"fd:3": "",

		// Not a spec at all. A watcher that cannot tell what it is looking at
		// watches nothing rather than guessing at a filename.
		"": "",
	} {
		if got := devicePath(spec); got != want {
			t.Errorf("devicePath(%q) = %q, want %q", spec, got, want)
		}
	}
}

// TestGraceIsLongerThanAnchorsOwnDialling is the arithmetic the whole watcher rests
// on. anchor redials an uplink on a 2s tick with a 45s dial timeout, and the slowest
// line conflux accepts needs ~25s for a realm handshake. A grace shorter than that
// would restart anchors that were about to come up on their own.
func TestGraceIsLongerThanAnchorsOwnDialling(t *testing.T) {
	const (
		anchorDialTimeout = 45 * time.Second
		slowestHandshake  = 25 * time.Second
	)

	if linkGrace <= anchorDialTimeout+slowestHandshake {
		t.Errorf("linkGrace is %s, which does not outlast a %s dial plus a %s handshake",
			linkGrace, anchorDialTimeout, slowestHandshake)
	}

	if linkCheckInterval >= linkGrace {
		t.Errorf("linkCheckInterval %s is not shorter than linkGrace %s, so the grace could never be observed",
			linkCheckInterval, linkGrace)
	}
}

// TestLinkIsDeadWhenTheDeviceGoes: an unplugged adapter is unambiguous, and is not
// made to wait out the grace period that exists for the ambiguous case.
func TestLinkIsDeadWhenTheDeviceGoes(t *testing.T) {
	s := &Supervisor{}

	var zeroSince time.Time

	missing := filepath.Join(t.TempDir(), "ttyUSB0")

	dead, reason := s.linkIsDead(t.Context(), missing, &zeroSince)
	if !dead {
		t.Fatal("a device that is not there should be a dead link")
	}

	if reason == "" {
		t.Error("a dead link should say why")
	}
}
