package version

import (
	"os"
	"strings"
	"testing"
)

// TestVersionMatchesFile holds the linker default and the VERSION file together.
//
// Two things name this build's version -- the Makefile, which stamps the file's
// contents through -ldflags, and the Version variable, which is what an unstamped
// `go build` reports. Nothing else makes them agree, and a release built one way
// reporting a different number from the same tree built the other way is the kind
// of thing nobody notices until an issue report names a version that never shipped.
func TestVersionMatchesFile(t *testing.T) {
	b, err := os.ReadFile("../../VERSION")
	if err != nil {
		t.Fatalf("read VERSION: %v", err)
	}

	want := strings.TrimSpace(string(b))
	if want == "" {
		t.Fatal("VERSION is empty")
	}

	if Version != want {
		t.Errorf("version.Version = %q, VERSION file = %q; change both or neither", Version, want)
	}
}
