package paths

import (
	"path/filepath"
	"testing"
)

// TestMountAllowsExecReadsNothing: Windows mounts nothing noexec, so MountAllowsExec says so of any
// path, and reads nothing at it: Ephemeral asks it where Foreign found a candidate's way missing,
// and a lookup by name there would follow what any user may make in C:\ meanwhile -- a link to a
// share, which following signs this machine in to -- or find nothing. Windows-only, so it runs in
// CI's platforms job alone.
func TestMountAllowsExecReadsNothing(t *testing.T) {
	share := dirSymlink(t, filepath.Join(t.TempDir(), "cfx"), `\\192.0.2.1\conflux`)

	for _, p := range []string{filepath.Join(t.TempDir(), "not", "there"), share, filepath.Join(share, ephemeralName)} {
		if ok, err := MountAllowsExec(p); !ok || err != nil {
			t.Errorf("MountAllowsExec(%s) = %v, %v, want true, nil, with nothing read", p, ok, err)
		}
	}
}
