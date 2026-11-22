package pathstest

import (
	"os"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/veil-net/conflux/internal/paths"
	"github.com/veil-net/conflux/internal/privtest"
)

// Every test linking this package makes what it makes the Administrators', as every conflux process
// does as it starts (paths.ElevatedDefaultOwner), and roots it, its CONFLUX_DIRs among it, on a way
// the boot service trusts (privtest.ServiceTemp): EnsureAll holds an installation's way to the rule
// SYSTEM holds it to at every start, which the administrator's own profile, where %TEMP% is, does
// not pass. What conflux keeps in %ProgramData% -- an elevated reader's temporary anchorctl, and the
// platform's roots where no CONFLUX_DIR is set -- it keeps in the process's temporary directory too
// (paths.ProgramData): there, in a test's own where the test points TMP and TEMP at one, or in a folder
// of its own a test gives it (ProgramData).
func init() {
	if err := paths.ElevatedDefaultOwner(); err != nil {
		panic("pathstest: " + err.Error())
	}

	if err := privtest.ServiceTemp(); err != nil {
		panic("pathstest: " + err.Error())
	}

	paths.ProgramData = os.TempDir
}

// ProgramData keeps what conflux keeps in %ProgramData% in dir for the rest of the test, apart from the
// temporary directory, and is dir: for a test that asserts what goes there and what does not.
func ProgramData(tb testing.TB, dir string) string {
	tb.Helper()

	was := paths.ProgramData
	paths.ProgramData = func() string { return dir }

	tb.Cleanup(func() { paths.ProgramData = was })

	return dir
}

// NotAsConfluxMakesIt makes p, a root of conflux's, or a file or a folder in one, this administrator's, as
// an earlier conflux left the service's copy on a Windows client: not as conflux makes one of its own,
// which the Administrators own.
func NotAsConfluxMakesIt(tb testing.TB, p string) {
	tb.Helper()

	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		tb.Fatal(err)
	}

	privtest.SetOwner(tb, p, user.User.Sid)
}
