package paths

import "os"

// mountAllowsExec is true wherever dir exists: Windows mounts nothing noexec.
func mountAllowsExec(dir string) (bool, error) {
	if _, err := os.Stat(dir); err != nil {
		return false, err
	}

	return true, nil
}
