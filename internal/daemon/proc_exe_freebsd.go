package daemon

import (
	"bytes"

	"golang.org/x/sys/unix"
)

// processExe is the executable a process runs.
func processExe(pid int) (string, error) {
	b, err := unix.SysctlRaw("kern.proc.pathname", pid)
	if err != nil {
		return "", err
	}

	path, _, _ := bytes.Cut(b, []byte{0})
	if len(path) == 0 {
		return "", errNoExePath
	}

	return string(path), nil
}
