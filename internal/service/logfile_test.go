//go:build darwin || freebsd

package service

import (
	"slices"
	"testing"

	"github.com/veil-net/conflux/internal/paths"
)

// TestTheServiceIsToldItsLog: launchd's and FreeBSD's registrations tell serve where its log
// is, so conflux writes it itself, stamped and moved aside when full, and leave the argv they
// were given as it was.
func TestTheServiceIsToldItsLog(t *testing.T) {
	args := []string{"serve"}

	got := withLog(args)
	if want := []string{"serve", "--log", logFile()}; !slices.Equal(got, want) {
		t.Errorf("withLog = %q, want %q", got, want)
	}

	if len(args) != 1 {
		t.Errorf("withLog changed the argv it was given: %q", args)
	}
}

// TestTheLogHintCanBeTypedAgain: the command status prints for reading the log is quoted for
// the shell it is pasted into, so a log in a folder with a space in its name -- macOS's
// /Library/Application Support -- is still named whole.
func TestTheLogHintCanBeTypedAgain(t *testing.T) {
	was := paths.SystemData
	paths.SystemData = func() string { return "/tmp/my conflux" }

	t.Cleanup(func() { paths.SystemData = was })

	if got, want := New().LogHint(), "tail -n 50 '/tmp/my conflux/.conflux/logs/conflux.log'"; got != want {
		t.Errorf("LogHint = %s, want %s", got, want)
	}
}
