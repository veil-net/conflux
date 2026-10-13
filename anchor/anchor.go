// Package anchor carries the anchor programs conflux drives.
//
// Exactly one pair is compiled into any given build. The seven bin_GOOS_GOARCH.go
// files are build-tagged so that a file whose tag is false is never compiled and
// its //go:embed never runs — a linux/amd64 conflux carries its own pair and not the
// fourteen binaries in bin/. Each file names its two files explicitly for the same
// reason: //go:embed bin, or a glob, would pull in all of them.
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

// minReal is well under the smallest real binary (anchorctl for linux/arm64, about
// 13 MB) and far above any placeholder.
const minReal = 5 << 20

// Supported reports whether this build carries a usable anchor pair.
//
// False for a GOOS/GOARCH conflux does not ship, and false for a build made from the
// placeholders `make anchor-bins` writes when no anchor checkout is available. The
// second case is why this is a size check and not just the build tag: the binaries
// are not in git, so a build with nothing real in anchor/bin is an ordinary thing to
// end up with, and it has to say so rather than ship a conflux that cannot start a
// daemon. An unshipped platform embeds nothing, which the same check answers.
var Supported = len(anchord) >= minReal && len(anchorctl) >= minReal

// Anchord is the daemon: it holds at most one anchor and outlives it.
func Anchord() []byte { return anchord }

// Anchorctl is the client: it drives the daemon over a Unix socket.
func Anchorctl() []byte { return anchorctl }

// The two SHA-256s, hex, stamped by the Makefile with -X from the very files this
// target's //go:embed names, so a released conflux knows its pair without reading it.
// Empty in a plain `go build` or `go test`, which compute them instead.
var anchordSHA256, anchorctlSHA256 string

// Digests are the two SHA-256s, hex: what `conflux version` prints, so a user comparing
// them against the release notes learns which anchor build they hold without running it,
// and what SetID is derived from.
//
// Stamped at build time, because every conflux invocation asks -- for SetID, before a
// pass-through or a status can do anything -- and reading the pair costs a pass over
// forty-odd megabytes: paged in from disk on a cold start, and a quarter of a second of
// SHA-256 on a core without SHA extensions. Computed, side by side, only where nothing
// stamped them.
var Digests = sync.OnceValues(func() (anchordSHA, anchorctlSHA string) {
	return digests(anchordSHA256, anchorctlSHA256)
})

// digests is the stamps when both are well formed, and the pair's own digests otherwise.
func digests(stampD, stampC string) (string, string) {
	if isDigest(stampD) && isDigest(stampC) {
		return stampD, stampC
	}

	return computeDigests()
}

func isDigest(s string) bool {
	if len(s) != sha256.Size*2 {
		return false
	}

	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}

	return true
}

func computeDigests() (anchordSHA, anchorctlSHA string) {
	var wg sync.WaitGroup

	wg.Go(func() {
		sum := sha256.Sum256(anchorctl)
		anchorctlSHA = hex.EncodeToString(sum[:])
	})

	sum := sha256.Sum256(anchord)
	anchordSHA = hex.EncodeToString(sum[:])

	wg.Wait()

	return anchordSHA, anchorctlSHA
}

// SetID names this exact pair, and is what the extraction directory is keyed on.
//
// Content-addressed rather than a version string, so that a conflux carrying
// different binaries extracts beside the old ones instead of over them. That is
// what makes an in-place upgrade safe: the running anchord keeps the file it has
// open, nothing hits ETXTBSY or a Windows sharing violation, and the old set is
// swept once the service restarts onto the new one.
//
// Derived from the two digests and the platform, so a stamped build answers with
// no read of the pair at all.
var SetID = sync.OnceValue(func() string { return setID(Digests()) })

func setID(anchordSHA, anchorctlSHA string) string {
	sum := sha256.Sum256([]byte("anchord " + anchordSHA + "\nanchorctl " + anchorctlSHA + "\n" +
		runtime.GOOS + "/" + runtime.GOARCH))

	return hex.EncodeToString(sum[:8])
}
