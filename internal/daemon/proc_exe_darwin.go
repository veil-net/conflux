package daemon

import (
	"bytes"

	"golang.org/x/sys/unix"
)

// processExe is the executable a process runs: the path it was started as, which
// kern.procargs2 gives after the argument count.
func processExe(pid int) (string, error) {
	b, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return "", err
	}

	if len(b) < 4 {
		return "", errNoExePath
	}

	path, _, _ := bytes.Cut(b[4:], []byte{0})
	if len(path) == 0 {
		return "", errNoExePath
	}

	return string(path), nil
}
