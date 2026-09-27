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
	"encoding/binary"
	"encoding/hex"
	"hash/crc32"
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
//
// A CRC-32C and the length of each binary rather than a cryptographic digest,
// because every conflux invocation asks and nothing here is adversarial: the bytes
// are this program's own, and the question is only whether they are the pair a
// directory already holds. SHA-256 over the pair costs a quarter of a second on a
// core without SHA extensions; Castagnoli has an instruction on amd64 and arm64.
var SetID = sync.OnceValue(func() string {
	table := crc32.MakeTable(crc32.Castagnoli)

	var b []byte
	for _, bin := range [][]byte{anchord, anchorctl} {
		b = binary.BigEndian.AppendUint32(b, crc32.Checksum(bin, table))
		b = binary.BigEndian.AppendUint64(b, uint64(len(bin)))
	}

	sum := sha256.Sum256(append(b, runtime.GOOS+"/"+runtime.GOARCH...))

	return hex.EncodeToString(sum[:8])
})

// Digests are the two SHA-256s, hex, for `conflux version` to print. A user
// comparing them against the release notes learns which anchor build they hold
// without running it. Computed side by side, since each is most of a second of CPU
// on a core without SHA extensions.
var Digests = sync.OnceValues(func() (anchordSHA, anchorctlSHA string) {
	var wg sync.WaitGroup

	wg.Go(func() {
		sum := sha256.Sum256(anchorctl)
		anchorctlSHA = hex.EncodeToString(sum[:])
	})

	sum := sha256.Sum256(anchord)
	anchordSHA = hex.EncodeToString(sum[:])

	wg.Wait()

	return anchordSHA, anchorctlSHA
})
