package daemon

import (
	"os"
	"strconv"
	"strings"
)

// processExe is the executable a process runs. One deleted since -- a set the supervisor
// has swept -- is reported under its old path, which is the one recorded.
func processExe(pid int) (string, error) {
	exe, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")

	return strings.TrimSuffix(exe, " (deleted)"), err
}
