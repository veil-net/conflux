package paths

// MountAllowsExec is true, and reads nothing at dir: Windows mounts nothing noexec.
func MountAllowsExec(string) (bool, error) { return true, nil }
