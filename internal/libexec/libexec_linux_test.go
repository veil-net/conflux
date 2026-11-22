package libexec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/pathstest"
)

// TestUsageRunsFromWhereExecIsAllowed: a temporary directory on a filesystem mounted noexec,
// as /tmp is on a hardened host, cannot run the anchorctl help copies there, so the copy
// goes to the next place that can: the user's cache directory, made where a fresh account
// has none yet. A TMPDIR under /proc, which is noexec everywhere, stands in for one.
func TestUsageRunsFromWhereExecIsAllowed(t *testing.T) {
	anchortest.Require(t)

	d := pathstest.RootedIn(t, t.TempDir())
	pathstest.Temporary(t, "/proc/conflux-noexec-tmp")

	cache := filepath.Join(t.TempDir(), "cache")
	t.Setenv("XDG_CACHE_HOME", cache)

	bin, _, err := forUsage(t, d)
	if err != nil {
		t.Fatalf("ForUsage: %v", err)
	}

	if !strings.HasPrefix(bin, cache+string(filepath.Separator)) {
		t.Errorf("the temporary anchorctl is %s, want it in the cache directory %s", bin, cache)
	}

	if out, err := exec.Command(bin, "help").CombinedOutput(); err != nil || !strings.Contains(string(out), "anchorctl") {
		t.Errorf("the temporary anchorctl did not answer help: %v\n%s", err, out)
	}
}

// TestSELinuxHintQuotesTheDirectory: the commands SELinux's hint gives are pasted into a shell
// as root, so a directory holding a space and a quote reaches each of them whole.
func TestSELinuxHintQuotesTheDirectory(t *testing.T) {
	got := selinuxHint("/srv/con flux/it's/bin")

	want := `  try:  sudo semanage fcontext -a -t bin_t '/srv/con flux/it'\''s/bin(/.*)?' && ` +
		`sudo restorecon -R '/srv/con flux/it'\''s/bin'`
	if !strings.HasSuffix(got, "\n"+want) {
		t.Errorf("selinuxHint =\n%s\nwant it to hold\n%s", got, want)
	}
}

// TestCannotExecuteGivesTheSELinuxHint: where SELinux is enforcing, a set refused at exec on a
// filesystem that allows it is probably labelled var_lib_t, so what cannotExecute says carries
// the hint; where it is not, it says nothing of SELinux. The directory this test runs from is on
// a filesystem that allows exec.
func TestCannotExecuteGivesTheSELinuxHint(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}

	bin := filepath.Dir(exe)

	enforce := filepath.Join(t.TempDir(), "enforce")

	defer func(was string) { selinuxEnforce = was }(selinuxEnforce)
	selinuxEnforce = enforce

	for _, c := range []struct {
		enforcing string
		hint      bool
	}{{"1\n", true}, {"0\n", false}} {
		if err := os.WriteFile(enforce, []byte(c.enforcing), 0o600); err != nil {
			t.Fatal(err)
		}

		got := cannotExecute(bin)
		if strings.Contains(got, selinuxHint(bin)) != c.hint || !c.hint && strings.Contains(got, "SELinux") {
			t.Errorf("with SELinux's enforce %q, cannotExecute =\n%s\nwant the SELinux hint: %v", c.enforcing, got, c.hint)
		}
	}
}
