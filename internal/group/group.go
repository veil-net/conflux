//go:build !windows

package group

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"sync"

	"github.com/veil-net/conflux/internal/privcheck"
)

// Users are the accounts the group of that name, whose id is gid, lets in: the members it
// lists, and every account it is the primary group of.
func Users(name, gid string) ([]string, error) {
	group, err := record(name)
	if err != nil {
		return nil, err
	}

	users, err := accounts()
	if err != nil {
		return nil, err
	}

	return usersFrom(runtime.GOOS, group, users, gid), nil
}

// Cached is Users for a process that asks of the same groups again and again, as every walk of a
// directory's parents does: each group's record, and the account database behind them all, read
// once for the process and kept, what failed to be read excepted. A change to who a group lets in
// while the process runs is not seen by it; account, which makes such changes, asks Users.
func Cached(name, gid string) ([]string, error) {
	cache.Lock()
	defer cache.Unlock()

	group, ok := cache.records[name]
	if !ok {
		var err error
		if group, err = record(name); err != nil {
			return nil, err
		}

		cache.records[name] = group
	}

	if cache.accounts == nil {
		users, err := accounts()
		if err != nil {
			return nil, err
		}

		cache.accounts = &users
	}

	return usersFrom(runtime.GOOS, group, *cache.accounts, gid), nil
}

// cache is what Cached has read.
var cache = struct {
	sync.Mutex
	records  map[string]string
	accounts *string
}{records: map[string]string{}}

// record is the group name's record: dscl's on macOS, else getent's, or, where there is no getent --
// a bare busybox has none -- its line of /etc/group.
func record(name string) (string, error) {
	switch {
	case runtime.GOOS == "darwin":
		return output("dscl", ".", "-read", "/Groups/"+name)
	case files():
		groups, err := os.ReadFile("/etc/group")
		if err != nil {
			return "", err
		}

		var group string

		for line := range strings.Lines(string(groups)) {
			if strings.HasPrefix(line, name+":") {
				group = line
			}
		}

		return group, nil
	}

	return output("getent", "group", name)
}

// accounts is every account's primary group, as dscl lists them on macOS, else getent's passwd
// database, or /etc/passwd where there is no getent.
func accounts() (string, error) {
	switch {
	case runtime.GOOS == "darwin":
		return output("dscl", ".", "-list", "/Users", "PrimaryGroupID")
	case files():
		users, err := os.ReadFile("/etc/passwd")

		return string(users), err
	}

	return output("getent", "passwd")
}

// files reports whether the databases are read from their files: where there is no getent, outside
// macOS.
func files() bool {
	_, err := exec.LookPath("getent")

	return err != nil && runtime.GOOS != "darwin"
}

// output is what argv, run, prints, or why it failed, naming it.
var output = func(argv ...string) (string, error) {
	out, err := exec.Command(argv[0], argv[1:]...).Output() //nolint:gosec // our own argv
	if err != nil {
		return "", fmt.Errorf("%s: %w", privcheck.Command(argv...), err)
	}

	return string(out), nil
}

// usersFrom reads Users' two answers: getent's group line and passwd database, or
// dscl's group record and its list of each account's primary group.
func usersFrom(goos, group, users, gid string) []string {
	var out []string

	if goos == "darwin" {
		for line := range strings.Lines(group) {
			if rest, ok := strings.CutPrefix(line, "GroupMembership:"); ok {
				out = append(out, strings.Fields(rest)...)
			}
		}

		for line := range strings.Lines(users) {
			if f := strings.Fields(line); len(f) == 2 && f[1] == gid {
				out = append(out, f[0])
			}
		}
	} else {
		if f := strings.Split(strings.TrimSpace(group), ":"); len(f) == 4 && f[3] != "" {
			out = append(out, strings.Split(f[3], ",")...)
		}

		for line := range strings.Lines(users) {
			if f := strings.Split(line, ":"); len(f) >= 4 && f[3] == gid {
				out = append(out, f[0])
			}
		}
	}

	slices.Sort(out)

	return slices.Compact(out)
}
