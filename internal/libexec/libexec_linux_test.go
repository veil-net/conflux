package libexec

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/veil-net/conflux/internal/anchortest"
	"github.com/veil-net/conflux/internal/paths"
)

// TestUsageRunsFromWhereExecIsAllowed: a temporary directory on a filesystem mounted noexec,
// as /tmp is on a hardened host, cannot run the anchorctl help copies there, so the copy
// goes to the next place that can: the user's cache directory, made where a fresh account
// has none yet. A TMPDIR under /proc, which is noexec everywhere, stands in for one.
func TestUsageRunsFromWhereExecIsAllowed(t *testing.T) {
	anchortest.Require(t)

	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONFLUX_DIR", filepath.Join(parent, "never"))
	t.Setenv("TMPDIR", "/proc/conflux-noexec-tmp")

	cache := filepath.Join(t.TempDir(), "cache")
	t.Setenv("XDG_CACHE_HOME", cache)

	bin, done, err := ForUsage(paths.Default())
	if err != nil {
		t.Fatalf("ForUsage: %v", err)
	}

	defer done()

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
		`sudo restorecon -R '/srv/con flux/it'\''s/bin'` + "\n"
	if !strings.Contains(got, "\n"+want) {
		t.Errorf("selinuxHint =\n%s\nwant it to hold\n%s", got, want)
	}
}
