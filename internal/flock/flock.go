// Package flock takes exclusive advisory locks on files.
//
// libexec serialises the extraction of the embedded anchor pair with one, and the
// daemon everything that rewrites the manifest and the state -- a bring-up, a renewal,
// the uplink watcher's count, `conflux enrol` -- with another. A third keeps one
// supervisor per root, and Held on anchord's own socket lock says whether a daemon is
// serving there. The primitive is three lines of platform
// code either way, which is exactly the size of thing that gets copied rather than
// shared and then diverges on the platform nobody develops on.
package flock
