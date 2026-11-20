//go:build !windows

package group

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"

	"github.com/veil-net/conflux/internal/privcheck"
)

// Users are the accounts the group of that name, whose id is gid, lets in: the members it
// lists, and every account it is the primary group of.
func Users(name, gid string) ([]string, error) {
	var groupArgv, usersArgv []string

	// A bare busybox has no getent, and only the files to ask.
	if _, err := exec.LookPath("getent"); err != nil && runtime.GOOS != "darwin" {
		return usersFromFiles(name, gid)
	}

	if runtime.GOOS == "darwin" {
		groupArgv = []string{"dscl", ".", "-read", "/Groups/" + name}
		usersArgv = []string{"dscl", ".", "-list", "/Users", "PrimaryGroupID"}
	} else {
		groupArgv = []string{"getent", "group", name}
		usersArgv = []string{"getent", "passwd"}
	}

	group, err := exec.Command(groupArgv[0], groupArgv[1:]...).Output() //nolint:gosec // our own argv
	if err != nil {
		return nil, fmt.Errorf("%s: %w", privcheck.Command(groupArgv...), err)
	}

	users, err := exec.Command(usersArgv[0], usersArgv[1:]...).Output() //nolint:gosec // our own argv
	if err != nil {
		return nil, fmt.Errorf("%s: %w", privcheck.Command(usersArgv...), err)
	}

	return usersFrom(runtime.GOOS, string(group), string(users), gid), nil
}

// usersFromFiles is Users read from /etc/group and /etc/passwd.
func usersFromFiles(name, gid string) ([]string, error) {
	groups, err := os.ReadFile("/etc/group")
	if err != nil {
		return nil, err
	}

	users, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return nil, err
	}

	var group string

	for line := range strings.Lines(string(groups)) {
		if strings.HasPrefix(line, name+":") {
			group = line
		}
	}

	return usersFrom(runtime.GOOS, group, string(users), gid), nil
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
