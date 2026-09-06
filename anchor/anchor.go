// Package anchor carries the anchor programs conflux drives.
//
// Exactly one pair is compiled into any given build. The eight bin_GOOS_GOARCH.go
// files are build-tagged so that a file whose tag is false is never compiled and
// its //go:embed never runs — a linux/amd64 conflux carries the ~43 MB it needs and
// not the ~324 MB in bin/. Each file names its two files explicitly for the same
// reason: //go:embed bin, or a glob, would pull in all sixteen.
//
// The binaries in bin/ are release builds: pinned to the production genesis and
// garbled. anchorctl among them is the -tags lockdown build, which cannot mint a
// realm root. anchoradmin, which can, is deliberately not here and must never be.
package anchor

import (
	"crypto/sha256"
	"encoding/hex"
	"runtime"
	"sync"
)

// minReal is well under the smallest real binary (anchorctl-linux-arm64, about
// 12.8 MB) and far above any placeholder.
const minReal = 5 << 20

// Supported reports whether this build carries a usable anchor pair.
//
// False for a GOOS/GOARCH conflux does not ship, and false for a build made from the
// placeholders `make anchor-bins` writes when no anchor checkout is available. The
// second case is why this is a size check and not just the build tag: the binaries
// are not in git, so a build with nothing real in anchor/bin is an ordinary thing to
// end up with, and it has to say so rather than ship a conflux that cannot start a
// daemon.
var Supported = supported && len(anchord) >= minReal && len(anchorctl) >= minReal

// Anchord is the daemon: it holds at most one anchor and outlives it.
func Anchord() []byte { return anchord }

// Anchorctl is the client: it drives the daemon over a Unix socket.
func Anchorctl() []byte { return anchorctl }

// SetID names this exact pair, and is what the extraction directory is keyed on.
//
// Content-addressed rather than a version string, so that a conflux carrying
// different binaries extracts beside the old ones instead of over them. That is
// what makes an in-place upgrade safe: the running anchord keeps the file it has
// open, nothing hits ETXTBSY or a Windows sharing violation, and the old set is
// swept once the service restarts onto the new one.
var SetID = sync.OnceValue(func() string {
	a := sha256.Sum256(anchord)
	c := sha256.Sum256(anchorctl)

	h := sha256.New()
	h.Write(a[:])
	h.Write(c[:])
	h.Write([]byte(runtime.GOOS + "/" + runtime.GOARCH))

	return hex.EncodeToString(h.Sum(nil))[:16]
})

// Digests are the two SHA-256s, hex, for `conflux version` to print. A user
// comparing them against the release notes learns which anchor build they hold
// without running it.
var Digests = sync.OnceValues(func() (anchordSHA, anchorctlSHA string) {
	a := sha256.Sum256(anchord)
	c := sha256.Sum256(anchorctl)

	return hex.EncodeToString(a[:]), hex.EncodeToString(c[:])
})
