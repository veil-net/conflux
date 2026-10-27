package account

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Kill ends every process running as uid, and returns once none is left. Every process
// of the account is one anchord started, or one that anchord started: killing its group
// does not reach a child that left it, and such a child could otherwise hold the socket's
// lock, or the socket path itself, against the next anchord.
func Kill(uid int) error {
	for round := 0; round < 50; round++ {
		pids, err := processesOf(uid)
		if err != nil {
			return err
		}

		if len(pids) == 0 {
			return nil
		}

		for _, pid := range pids {
			_ = unix.Kill(pid, unix.SIGKILL)
		}

		time.Sleep(20 * time.Millisecond)
	}

	return fmt.Errorf("processes of uid %d are still running", uid)
}

// processesOf are the live processes whose real or effective uid is uid, as /proc says.
func processesOf(uid int) ([]int, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	want := strconv.Itoa(uid)

	var pids []int

	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}

		ruid, euid, err := uidsOf(pid)
		if errors.Is(err, os.ErrNotExist) {
			continue // gone already
		}

		if err == nil && (ruid == want || euid == want) && !zombie(pid) {
			pids = append(pids, pid)
		}
	}

	return pids, nil
}

func uidsOf(pid int) (ruid, euid string, err error) {
	f, err := os.Open("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "Uid:"); ok {
			if fields := strings.Fields(rest); len(fields) >= 2 {
				return fields[0], fields[1], nil
			}
		}
	}

	return "", "", errors.New("no Uid line")
}

// zombie reports a process that has exited and waits only for its parent to reap it,
// which no signal ends and which holds nothing.
func zombie(pid int) bool {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return true
	}

	// The state follows the command name, which is in parentheses and may hold anything.
	if i := strings.LastIndexByte(string(b), ')'); i >= 0 && i+2 < len(b) {
		return b[i+2] == 'Z' || b[i+2] == 'X'
	}

	return false
}
