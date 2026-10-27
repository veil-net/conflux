//go:build !windows

package paths

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mode(t *testing.T, dir string) os.FileMode {
	t.Helper()

	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}

	return fi.Mode().Perm()
}

// TestEnsureAllNarrowsAnOpenRoot: a root of conflux's own that something left at 0755 holds
// the manifest in a directory anybody can traverse, so it is narrowed, not adopted as found.
func TestEnsureAllNarrowsAnOpenRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}

	t.Setenv("CONFLUX_DIR", root)

	if err := Default().EnsureAll(); err != nil {
		t.Fatal(err)
	}

	if got := mode(t, root); got != 0o700 {
		t.Errorf("the root is %#o after EnsureAll, want 0700", got)
	}
}

// TestSecureRefusesARootAnotherAccountOwns: whatever another account put in a directory
// it made is not used, and the directory is left exactly as it was found.
func TestSecureRefusesARootAnotherAccountOwns(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	err := secureAs(dir, os.Geteuid()+1)
	if err == nil {
		t.Fatal("a root owned by another uid was accepted")
	}

	if !strings.Contains(err.Error(), "belongs to") {
		t.Errorf("the refusal does not say why: %v", err)
	}

	if got := mode(t, dir); got != 0o755 {
		t.Errorf("the refused root was changed to %#o; a refusal must change nothing", got)
	}
}

// TestSecureNamesRootWhenRootOwnsIt: the common way to meet a root-owned root is to have
// forgotten sudo, so that is what the refusal says. Safe as any user: it refuses first.
func TestSecureNamesRootWhenRootOwnsIt(t *testing.T) {
	err := secureAs("/", 1000)
	if err == nil || !strings.Contains(err.Error(), "belongs to root") {
		t.Fatalf("secureAs(\"/\", 1000) = %v, want a refusal naming root", err)
	}
}

// TestSecureFollowsASymlinkOnlyToItsOwnersDirectory: a root that is a link is held to the
// owner of the link and of what it points at.
func TestSecureFollowsASymlinkOnlyToItsOwnersDirectory(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "root")

	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(target, 0o750); err != nil {
		t.Fatal(err)
	}

	if err := secure(link); err != nil {
		t.Fatalf("a link to a directory of our own was refused: %v", err)
	}

	if got := mode(t, target); got != 0o700 {
		t.Errorf("the link's target is %#o, want 0700", got)
	}

	if err := secureAs(link, os.Geteuid()+1); err == nil {
		t.Error("a link another uid owns was accepted")
	}
}

// TestEnsureAllLeavesTheSharedLogAlone: macOS and FreeBSD write the service's log into the
// system's /var/log, which is not conflux's to narrow.
func TestEnsureAllLeavesTheSharedLogAlone(t *testing.T) {
	shared := t.TempDir()
	if err := os.Chmod(shared, 0o755); err != nil {
		t.Fatal(err)
	}

	defer func(was string) { sharedLog = was }(sharedLog)
	sharedLog = shared

	root := t.TempDir()
	d := Dirs{Config: root, State: root, Run: filepath.Join(root, "run"), Log: shared}

	if err := d.EnsureAll(); err != nil {
		t.Fatal(err)
	}

	if got := mode(t, shared); got != 0o755 {
		t.Errorf("the shared log directory became %#o; conflux must leave it as the system made it", got)
	}
}

// TestSecureKeepsRootsPassThroughGroup: a root of root's at 0710 is how the supervisor
// lets anchord's own account pass through to what it runs, and every conflux command
// would otherwise cut a running anchord off; anything wider is still narrowed.
func TestSecureKeepsRootsPassThroughGroup(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("a directory of root's needs root")
	}

	dir := t.TempDir()

	if err := os.Chmod(dir, 0o710); err != nil {
		t.Fatal(err)
	}

	if err := secure(dir); err != nil {
		t.Fatal(err)
	}

	if got := mode(t, dir); got != 0o710 {
		t.Errorf("a root's 0710 was changed to %#o", got)
	}

	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}

	if err := secure(dir); err != nil {
		t.Fatal(err)
	}

	if got := mode(t, dir); got != 0o700 {
		t.Errorf("a root's 0750 is %#o after secure, want 0700", got)
	}
}
