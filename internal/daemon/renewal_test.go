package daemon

import (
	"testing"
	"time"
)

var (
	issued  = time.Date(2026, 9, 6, 0, 0, 0, 0, time.UTC)
	expires = issued.Add(7 * 24 * time.Hour) // the alpha realm's window
)

func TestRenewAtIsTwoThirdsOfTheObservedWindow(t *testing.T) {
	at := RenewAt(issued, expires)

	// Two thirds of seven days is four days and sixteen hours.
	want := issued.Add(4*24*time.Hour + 16*time.Hour)
	if !at.Equal(want) {
		t.Errorf("RenewAt = %v, want %v", at, want)
	}

	// And the point of computing it rather than hardcoding seven days: a window of
	// another length divides the same way.
	short := issued.Add(3 * time.Hour)
	if got, want := RenewAt(issued, short), issued.Add(2*time.Hour); !got.Equal(want) {
		t.Errorf("RenewAt for a 3h window = %v, want %v", got, want)
	}
}

func TestDueAt(t *testing.T) {
	cases := []struct {
		when string
		now  time.Time
		want bool
	}{
		{"just issued", issued.Add(time.Minute), false},
		{"halfway", issued.Add(84 * time.Hour), false},
		{"a minute before two thirds", issued.Add(4*24*time.Hour + 16*time.Hour - time.Minute), false},
		{"at two thirds", issued.Add(4*24*time.Hour + 16*time.Hour), true},
		{"past expiry", expires.Add(time.Hour), true},
		{"a month past expiry", expires.Add(30 * 24 * time.Hour), true},
	}

	for _, tc := range cases {
		if got := DueAt(issued, expires, tc.now); got != tc.want {
			t.Errorf("%s: DueAt = %v, want %v", tc.when, got, tc.want)
		}
	}
}

// TestDueAtWithoutIssuedAt: a document that does not say when it was signed still
// has to renew before it lapses, not after.
func TestDueAtWithoutIssuedAt(t *testing.T) {
	if DueAt(time.Time{}, expires, expires.Add(-72*time.Hour)) {
		t.Error("renewed three days out with a 48h fallback lead")
	}

	if !DueAt(time.Time{}, expires, expires.Add(-24*time.Hour)) {
		t.Error("did not renew one day out with a 48h fallback lead")
	}
}

// TestDueAtWithNoExpiry: an unreadable expiry means renew, never "forever".
func TestDueAtWithNoExpiry(t *testing.T) {
	if !DueAt(issued, time.Time{}, issued) {
		t.Error("a credential with no stated expiry should be renewed, not trusted")
	}
}

// TestSleepIsClamped is what saves a laptop that was suspended for months: the
// timer is recomputed against the wall clock at least every six hours.
func TestSleepIsClamped(t *testing.T) {
	cases := []struct {
		when string
		now  time.Time
		want time.Duration
	}{
		{"long before renewal", issued, MaxSleep},
		{"well past expiry", expires.Add(365 * 24 * time.Hour), MinSleep},
		{"just before renewal", RenewAt(issued, expires).Add(-30 * time.Second), MinSleep},
		{"an hour before renewal", RenewAt(issued, expires).Add(-time.Hour), time.Hour},
	}

	for _, tc := range cases {
		got := SleepUntilRenewal(issued, expires, tc.now)
		if got != tc.want {
			t.Errorf("%s: sleep = %v, want %v", tc.when, got, tc.want)
		}

		if got < MinSleep || got > MaxSleep {
			t.Errorf("%s: sleep = %v, outside [%v, %v]", tc.when, got, MinSleep, MaxSleep)
		}
	}
}

// TestSleepIsNeverNegative guards the arithmetic against a clock that moved
// backwards, which would otherwise produce a time.After of a negative duration and
// a hot loop.
func TestSleepIsNeverNegative(t *testing.T) {
	for _, now := range []time.Time{
		expires.Add(time.Hour),
		issued.Add(-100 * 24 * time.Hour),
		time.Time{},
	} {
		if got := SleepUntilRenewal(issued, expires, now); got <= 0 {
			t.Errorf("sleep at %v = %v", now, got)
		}
	}
}
