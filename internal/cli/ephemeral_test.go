package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/pathstest"
)

// TestManifestIsForAnEphemeralRun: a credential named without --ephemeral is one to keep,
// which is conflux enrol's, and the refusal says so before anything of the machine's is read.
func TestManifestIsForAnEphemeralRun(t *testing.T) {
	d := pathstest.RootedIn(t, t.TempDir())

	for _, verb := range [][]string{{"up"}, {"proxy", "8080=127.0.0.1:3000"}} {
		_, errOut, code := capture(t, append(verb, "--manifest", "-")...)
		if code == ExitOK || !strings.Contains(errOut, "conflux enrol --manifest") {
			t.Errorf("%s --manifest without --ephemeral: exit %d, %q; want a refusal naming conflux enrol", verb[0], code, errOut)
		}
	}

	if _, err := os.Stat(d.ConfigFile()); err == nil {
		t.Error("a refused run wrote a configuration")
	}
}

// TestEphemeralIsLinuxAlone: an ephemeral run is Linux's alone, so where there is none to run
// (ephemeral nil: everywhere but Linux) up and proxy refuse --ephemeral, exit 2, saying so, before
// anything is read -- the credential --manifest names among it -- or asked for, root included.
func TestEphemeralIsLinuxAlone(t *testing.T) {
	was := ephemeral
	ephemeral = nil

	t.Cleanup(func() { ephemeral = was })

	manifest := filepath.Join(t.TempDir(), "not-there.b64")

	for _, args := range [][]string{
		{"up", "--ephemeral"},
		{"proxy", "8080=127.0.0.1:3000", "--ephemeral", "--manifest", manifest},
	} {
		if _, errOut, code := capture(t, args...); code != ExitUsage || !strings.Contains(errOut, "Linux") {
			t.Errorf("%s with no ephemeral runs exited %d, want %d saying it is Linux's alone:\n%s",
				strings.Join(args, " "), code, ExitUsage, errOut)
		}
	}
}
