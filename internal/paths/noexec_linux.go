package paths

import "golang.org/x/sys/unix"

// mountAllowsExec reports whether the filesystem holding dir is mounted without noexec.
func mountAllowsExec(dir string) (bool, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return false, err
	}

	return st.Flags&unix.ST_NOEXEC == 0, nil
}
