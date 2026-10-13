package daemon

import "time"

// renewFraction is where in a credential's window conflux asks for the next one.
//
// Two thirds, which is what the enrolment API's own documentation specifies: renew
// on launch and on a timer at two thirds of notAfter. For the alpha realm's
// thirty-day window that is day twenty, leaving ten days of retry budget -- early
// enough to survive a long outage, late enough that a machine which is always on
// renews about once every three weeks rather than every day.
const renewFraction = 2.0 / 3.0

// fallbackLead is used when issuedAt is missing or nonsensical, so that a document
// conflux cannot reason about still renews before it lapses rather than after.
const fallbackLead = 48 * time.Hour

// Sleep bounds. A computed wait is clamped into these on every cycle rather than
// trusted once.
//
// The ceiling is what saves a suspended laptop. A machine that slept for six months
// wakes with a timer that was armed against a wall clock from another era; waking at
// least every six hours to recompute means it renews within six hours of resuming
// instead of never. The floor stops a pathological window becoming a busy loop.
const (
	minSleep = time.Minute
	maxSleep = 6 * time.Hour
)

// renewAt is the moment a credential should be replaced.
func renewAt(issuedAt, notAfter time.Time) time.Time {
	if notAfter.IsZero() {
		// Nothing to reason about: renew at once rather than assume forever.
		return time.Time{}
	}

	if issuedAt.IsZero() || !issuedAt.Before(notAfter) {
		return notAfter.Add(-fallbackLead)
	}

	window := notAfter.Sub(issuedAt)

	return issuedAt.Add(time.Duration(float64(window) * renewFraction))
}

// dueAt reports whether a credential issued and expiring at these times should be
// renewed as of now.
func dueAt(issuedAt, notAfter, now time.Time) bool {
	at := renewAt(issuedAt, notAfter)
	if at.IsZero() {
		return true
	}

	return !now.Before(at)
}

// sleepUntilRenewal is how long to wait before the next check, clamped.
func sleepUntilRenewal(issuedAt, notAfter, now time.Time) time.Duration {
	at := renewAt(issuedAt, notAfter)
	if at.IsZero() {
		return minSleep
	}

	d := at.Sub(now)

	switch {
	case d < minSleep:
		return minSleep
	case d > maxSleep:
		return maxSleep
	default:
		return d
	}
}
