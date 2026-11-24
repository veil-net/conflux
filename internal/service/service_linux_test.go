package service

import (
	"os"
	"path/filepath"
	"testing"
)

// TestEveryDropinIsRemoved: systemd reads drop-ins for the unit from /etc and from /run, an
// administrator's and systemctl set-property's (system.control) alike, persistent and for
// the boot, and any of them would make the unit that runs other than the one conflux writes.
// Another unit's are left alone.
func TestEveryDropinIsRemoved(t *testing.T) {
	root := t.TempDir()

	dirs := []string{
		"etc/systemd/system/conflux.service.d",
		"etc/systemd/system.control/conflux.service.d",
		"run/systemd/system/conflux.service.d",
		"run/systemd/system.control/conflux.service.d",
	}

	const otherDir = "etc/systemd/system.control/other.service.d"

	for _, dir := range append(dirs, otherDir) {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}

		if err := os.WriteFile(filepath.Join(root, dir, "50-CPUWeight.conf"), []byte("[Service]\nCPUWeight=50\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	if found, err := removeDropins(root); err != nil || !found {
		t.Fatalf("removeDropins = %v, %v; want the drop-ins found and removed", found, err)
	}

	for _, dir := range dirs {
		if _, err := os.Lstat(filepath.Join(root, dir)); !os.IsNotExist(err) {
			t.Errorf("/%s is still there (%v)", dir, err)
		}
	}

	if _, err := os.Stat(filepath.Join(root, otherDir)); err != nil {
		t.Errorf("another unit's drop-ins went too: %v", err)
	}

	if found, err := removeDropins(root); err != nil || found {
		t.Errorf("removeDropins with none left = %v, %v; want nothing found", found, err)
	}
}
