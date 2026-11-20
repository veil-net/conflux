//go:build darwin || freebsd

package service

import (
	"slices"
	"testing"
)

// TestTheServiceIsToldItsLog: launchd's and FreeBSD's registrations tell serve where its log
// is, so conflux writes it itself, stamped and moved aside when full, and leave the argv they
// were given as it was.
func TestTheServiceIsToldItsLog(t *testing.T) {
	args := []string{"serve", "--dir", "/srv/x"}

	got := withLog(args)
	if want := []string{"serve", "--dir", "/srv/x", "--log", logFile()}; !slices.Equal(got, want) {
		t.Errorf("withLog = %q, want %q", got, want)
	}

	if len(args) != 3 {
		t.Errorf("withLog changed the argv it was given: %q", args)
	}
}

// TestTheLogHintCanBeTypedAgain: the command status prints for reading the log is quoted for
// the shell it is pasted into, so a CONFLUX_DIR with a space in it still names the log.
func TestTheLogHintCanBeTypedAgain(t *testing.T) {
	t.Setenv("CONFLUX_DIR", "/tmp/my conflux")

	if got, want := New().LogHint(), "tail -n 50 '/tmp/my conflux/logs/conflux.log'"; got != want {
		t.Errorf("LogHint = %s, want %s", got, want)
	}
}
