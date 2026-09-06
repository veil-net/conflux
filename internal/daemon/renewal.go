package daemon

import "time"

// RenewFraction is where in a credential's window conflux asks for the next one.
//
// Two thirds, which is what the enrolment API's own documentation specifies: renew
// on launch and on a timer at two thirds of notAfter. For the alpha realm's
// seven-day window that is day 4.67, leaving fifty-six hours of retry budget --
// early enough to survive a long outage, late enough that a machine which is always
// on renews twice a fortnight rather than twice a day.
const RenewFraction = 2.0 / 3.0

// FallbackLead is used when issuedAt is missing or nonsensical, so that a document
// conflux cannot reason about still renews before it lapses rather than after.
const FallbackLead = 48 * time.Hour

// Sleep bounds. A computed wait is clamped into these on every cycle rather than
// trusted once.
//
// The ceiling is what saves a suspended laptop. A machine that slept for six months
// wakes with a timer that was armed against a wall clock from another era; waking at
// least every six hours to recompute means it renews within six hours of resuming
// instead of never. The floor stops a pathological window becoming a busy loop.
const (
	MinSleep = time.Minute
	MaxSleep = 6 * time.Hour
)

// RenewAt is the moment a credential should be replaced.
func RenewAt(issuedAt, notAfter time.Time) time.Time {
	if notAfter.IsZero() {
		// Nothing to reason about: renew at once rather than assume forever.
		return time.Time{}
	}

	if issuedAt.IsZero() || !issuedAt.Before(notAfter) {
		return notAfter.Add(-FallbackLead)
	}

	window := notAfter.Sub(issuedAt)

	return issuedAt.Add(time.Duration(float64(window) * RenewFraction))
}

// DueAt reports whether a credential issued and expiring at these times should be
// renewed as of now.
func DueAt(issuedAt, notAfter, now time.Time) bool {
	at := RenewAt(issuedAt, notAfter)
	if at.IsZero() {
		return true
	}

	return !now.Before(at)
}

// SleepUntilRenewal is how long to wait before the next check, clamped.
func SleepUntilRenewal(issuedAt, notAfter, now time.Time) time.Duration {
	at := RenewAt(issuedAt, notAfter)
	if at.IsZero() {
		return MinSleep
	}

	d := at.Sub(now)

	switch {
	case d < MinSleep:
		return MinSleep
	case d > MaxSleep:
		return MaxSleep
	default:
		return d
	}
}
