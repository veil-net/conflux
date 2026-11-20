package paths

import "os"

// MountAllowsExec is true wherever dir exists: Windows mounts nothing noexec.
func MountAllowsExec(dir string) (bool, error) {
	if _, err := os.Stat(dir); err != nil {
		return false, err
	}

	return true, nil
}
