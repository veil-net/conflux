package paths

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestTheRootIsNotTheEnvironments: the root and the installed conflux are where Windows keeps
// ProgramData and Program Files, not where the environment of whoever runs conflux says, which
// would otherwise move the root -- and the copy of conflux the service runs as SYSTEM -- into a
// directory of their choosing.
func TestTheRootIsNotTheEnvironments(t *testing.T) {
	root, installed := platformRoot(), InstalledExecutable()

	elsewhere := t.TempDir()
	t.Setenv("ProgramData", elsewhere)
	t.Setenv("ProgramFiles", elsewhere)

	if got := platformRoot(); got != root || strings.HasPrefix(got, elsewhere) {
		t.Errorf("with %%ProgramData%% at %s the root is %s, not %s", elsewhere, got, root)
	}

	if got := InstalledExecutable(); got != installed || strings.HasPrefix(got, elsewhere) {
		t.Errorf("with %%ProgramFiles%% at %s the installed conflux is %s, not %s", elsewhere, got, installed)
	}

	if filepath.Base(root) != ".conflux" || !filepath.IsAbs(root) {
		t.Errorf("the root is %s, want an absolute .conflux", root)
	}
}
