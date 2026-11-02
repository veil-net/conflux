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
