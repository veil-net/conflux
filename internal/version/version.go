// Package version reports what this build is.
package version

import (
	"crypto/fips140"
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"

	"github.com/veil-net/conflux/anchor"
)

// Version is the release, injected at link time:
//
//	-ldflags "-X github.com/veil-net/conflux/internal/version.Version=v0.1.0"
//
// The default is not "dev". The VERSION file at the repository root is what this
// tree claims to be, the Makefile stamps that same string, and a plain `go build`
// that stamps nothing should not disagree with `make build` about what it just
// compiled. TestVersionMatchesFile holds the two together.
var Version = "1.0.0"

// Commit is the git revision, injected the same way. Left empty, it is recovered
// from the build info Go embeds, so `go build` alone still says something useful.
var Commit = ""

// UserAgent is what the enrolment client sends. It names the platform because the
// API's failures differ by it and a server log that cannot tell them apart is a
// server log that cannot help.
var UserAgent = sync.OnceValue(func() string {
	return fmt.Sprintf("conflux/%s (%s/%s)", Version, runtime.GOOS, runtime.GOARCH)
})

// Revision is Commit if it was stamped, and the VCS revision Go recorded otherwise.
var Revision = sync.OnceValue(func() string {
	if Commit != "" {
		return Commit
	}

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}

	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			return s.Value
		}
	}

	return "unknown"
})

// String is the one line `conflux version` leads with.
func String() string {
	return fmt.Sprintf("conflux %s (%s) %s/%s", Version, Revision(), runtime.GOOS, runtime.GOARCH)
}

// Anchor describes the embedded pair, so a user can tell which anchor build they
// are running without starting it — and so a bug report names it.
func Anchor() string {
	if !anchor.Supported {
		return fmt.Sprintf("no anchor binaries for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	anchordSHA, anchorctlSHA := anchor.Digests()

	return fmt.Sprintf("anchor set %s\n  anchord    %s\n  anchorctl  %s",
		anchor.SetID(), anchordSHA, anchorctlSHA)
}

// FIPS says whether this conflux runs in FIPS 140-3 mode, and against which Go Cryptographic
// Module: the line `conflux version` and `conflux status` give it.
func FIPS() string {
	return fipsLine(fips140.Version(), fips140.Enabled())
}

// fipsLine is FIPS for a given module version and mode, so each case can be asserted.
//
// "latest" is what crypto/fips140 reports for a build against the toolchain's own tree rather
// than a frozen module: an OpenBSD build, which the module refuses, or a plain `go build`
// without the Makefile's GOFIPS140. A frozen module with the mode switched off is refused at
// start (cli.fipsRefusal), so it never reaches a report.
func fipsLine(module string, enabled bool) string {
	switch {
	case enabled && module != "latest":
		return "on, Go Cryptographic Module " + module
	case enabled:
		return "on, against the toolchain's own module rather than a frozen one"
	case module == "latest":
		return "off, this build carries no frozen Go Cryptographic Module"
	default:
		return "off, switched off by GODEBUG in a build against Go Cryptographic Module " + module
	}
}
