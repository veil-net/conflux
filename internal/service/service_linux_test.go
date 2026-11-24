package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestTheUnitsFourDropinDirectoriesAreRemoved: systemd reads drop-ins for the unit from /etc and
// from /run, an administrator's and systemctl set-property's (system.control) alike, persistent
// and for the boot, and any of them would make the unit that runs other than the one conflux
// writes. Another unit's are left alone.
func TestTheUnitsFourDropinDirectoriesAreRemoved(t *testing.T) {
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

// TestRemoveSaysWhatItCouldNotRemove: what systemctl says is forgiven once the unit's file is
// gone -- a disable fails for a unit whose file went first -- but a file Remove could not remove
// is a trace of conflux left on the machine, said whatever became of the unit file.
func TestRemoveSaysWhatItCouldNotRemove(t *testing.T) {
	// A systemctl of the test's own, which answers every call and refuses a disable as systemd
	// does once the unit file is gone.
	onPath(t, map[string]string{
		"systemctl": "#!/bin/sh\n[ \"$1\" = disable ] && { echo 'Unit file conflux.service does not exist.' >&2; exit 1; }\nexit 0\n",
	})

	const dropin = "/etc/systemd/system.control/conflux.service.d"

	// registered is a root holding the unit, its wants link and a drop-in, with the one path
	// stuck, if any, a directory holding a file: a removal that cannot take it, root or not.
	registered := func(stuck string) string {
		root := t.TempDir()

		for _, dir := range []string{filepath.Dir(unitPath), filepath.Dir(wantsPath), dropin} {
			if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
				t.Fatal(err)
			}
		}

		if err := os.WriteFile(filepath.Join(root, dropin, "50-CPUWeight.conf"), nil, 0o644); err != nil {
			t.Fatal(err)
		}

		for _, path := range []string{unitPath, wantsPath} {
			var err error

			switch {
			case path == stuck:
				err = os.MkdirAll(filepath.Join(root, path, "held"), 0o755)
			case path == unitPath:
				err = os.WriteFile(filepath.Join(root, path), []byte("[Unit]\n"), 0o644)
			default:
				err = os.Symlink(unitPath, filepath.Join(root, path))
			}

			if err != nil {
				t.Fatal(err)
			}
		}

		return root
	}

	gone := func(root string, paths ...string) {
		t.Helper()

		for _, path := range paths {
			if _, err := os.Lstat(filepath.Join(root, path)); !os.IsNotExist(err) {
				t.Errorf("%s is still there (%v)", path, err)
			}
		}
	}

	t.Run("everything removed", func(t *testing.T) {
		root := registered("")

		if err := remove(root); err != nil {
			t.Errorf("remove = %v; want nil, the disable's refusal forgiven with the unit gone", err)
		}

		gone(root, unitPath, wantsPath, dropin)
	})

	t.Run("a wants link left", func(t *testing.T) {
		root := registered(wantsPath)

		err := remove(root)
		if err == nil || !strings.Contains(err.Error(), wantsPath) {
			t.Errorf("remove = %v; want the wants link it could not remove said, though the unit file went", err)
		}

		if err != nil && strings.Contains(err.Error(), "does not exist") {
			t.Errorf("remove = %v; want the disable's refusal forgiven, the unit file gone", err)
		}

		gone(root, unitPath, dropin)
	})

	t.Run("the unit file left", func(t *testing.T) {
		root := registered(unitPath)

		err := remove(root)
		if err == nil || !strings.Contains(err.Error(), unitPath) || !strings.Contains(err.Error(), "does not exist") {
			t.Errorf("remove = %v; want the unit file it could not remove and systemctl's refusal both said", err)
		}

		gone(root, wantsPath, dropin)
	})
}
