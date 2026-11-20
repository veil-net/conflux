package version

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// semver is MAJOR.MINOR.PATCH, with no leading zeros and no suffix.
var semver = regexp.MustCompile(`^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// TestVersionMatchesFile holds the linker default and the VERSION file together, and the file
// to MAJOR.MINOR.PATCH.
//
// Two things name this build's version -- the Makefile, which stamps the file's
// contents through -ldflags, and the Version variable, which is what an unstamped
// `go build` reports. Nothing else makes them agree, and a release built one way
// reporting a different number from the same tree built the other way is the kind
// of thing nobody notices until an issue report names a version that never shipped.
//
// The file is also the release's tag, verbatim (release.yml), so it is a version and nothing
// else: never `latest` or `dev-latest`, the moving releases' tags, which a release at it would
// delete and replace.
func TestVersionMatchesFile(t *testing.T) {
	b, err := os.ReadFile("../../VERSION")
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}

	want := strings.TrimSpace(string(b))
	if !semver.MatchString(want) {
		t.Fatalf("VERSION is %q, not MAJOR.MINOR.PATCH", want)
	}

	if Version != want {
		t.Errorf("version.Version = %q, VERSION file = %q; change both or neither", Version, want)
	}
}

// TestFIPSLine: what each combination of module and mode reports, so a build that is not in
// FIPS 140-3 mode never reads as one that is.
func TestFIPSLine(t *testing.T) {
	for _, c := range []struct {
		module  string
		enabled bool
		want    string
	}{
		{"v1.26.0", true, "on, Go Cryptographic Module v1.26.0"},
		{"latest", true, "on, against the toolchain's own module"},
		{"latest", false, "off, this build carries no frozen"},
		{"v1.26.0", false, "off, switched off by GODEBUG"},
	} {
		if got := fipsLine(c.module, c.enabled); !strings.HasPrefix(got, c.want) {
			t.Errorf("fipsLine(%q, %v) = %q, want it to start %q", c.module, c.enabled, got, c.want)
		}
	}
}
