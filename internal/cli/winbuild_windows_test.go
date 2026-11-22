package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/pathstest"
)

// TestAWindowsTooOldIsRefusedBeforeAnythingIsMade: anchord's control socket is an AF_UNIX socket,
// which Windows has from build 17063, first released as Windows 10 version 1803, so on an older
// build -- here 1709's, 16299, stood in for this one's -- every command is refused before it does
// anything, naming the build and the oldest conflux runs on, and exiting 70: one that would make
// the root (enrol, which makes it before it reads the file it is given), one that reads it
// (status), one passed through to anchorctl, and the version alike. Nothing is made. Windows-only,
// so it runs in CI's platforms job alone.
func TestAWindowsTooOldIsRefusedBeforeAnythingIsMade(t *testing.T) {
	was := windowsBuild
	t.Cleanup(func() { windowsBuild = was })

	windowsBuild = func() uint32 { return 16299 }

	above := pathstest.RootedIn(t, t.TempDir()).Root

	missing := filepath.Join(t.TempDir(), "missing.b64")

	for _, argv := range [][]string{{"enrol", "--manifest", missing}, {"status"}, {"peers"}, {"version"}} {
		_, errOut, code := capture(t, argv...)
		if code != ExitChildFailed || !strings.Contains(errOut, "build 16299") || !strings.Contains(errOut, "build 17134") {
			t.Errorf("conflux %s on build 16299 exited %d, want %d naming it and build 17134:\n%s",
				strings.Join(argv, " "), code, ExitChildFailed, errOut)
		}
	}

	if _, err := os.Lstat(above); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("conflux made %s on a Windows it refused (%v)", above, err)
	}
}
