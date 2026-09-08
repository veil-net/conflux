// Package flock takes exclusive advisory locks on files.
//
// Two callers want this and neither owns it: libexec serialises the extraction of
// the embedded anchor pair, and the renew path serialises a manual renewal against
// the supervisor's own timer. The primitive is three lines of platform code either
// way, which is exactly the size of thing that gets copied rather than shared and
// then diverges on the platform nobody develops on.
package flock
