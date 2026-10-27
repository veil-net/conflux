// Package account is the unprivileged account anchord runs as wherever its mode and the
// host let it: one per installation, made by conflux the first time it is needed and
// removed by `conflux uninstall`.
//
// One per installation rather than one per machine, so a CONFLUX_DIR installation beside
// the machine's own never shares an identity with it: an anchord of a test root could
// otherwise reach the real node's anchor directory, which that identity owns.
//
// The command lines are rendered here, without a build tag, as the systemd unit and the
// rc scripts are, so that every platform's are tested on every machine that builds
// conflux. What runs them is per platform.
package account

import (
	"errors"
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"github.com/veil-net/conflux/internal/paths"
)

// Comment is the account's comment (GECOS on Linux and the BSDs, RealName on macOS), and
// how conflux knows an account of this name is its own: one without it was made by
// somebody else, and is neither used nor removed.
const Comment = "conflux anchord"

// Account is one, as the system knows it.
type Account struct {
	Name string
	UID  int
	GID  int
}

// ErrConflict is an account or group of this installation's name that conflux did not
// make. anchord does not run as it, and uninstall leaves it alone.
var ErrConflict = errors.New("an account of that name exists and conflux did not make it")

// Name is this installation's account: conflux, or _conflux where the platform names its
// own daemons' accounts so, with a CONFLUX_DIR installation's scope after it.
func Name() string { return nameFor(runtime.GOOS, paths.Scope()) }

func nameFor(goos, scope string) string {
	base := "conflux"
	if goos == "darwin" || goos == "openbsd" {
		base = "_conflux"
	}

	return base + scope
}

// String is the account as a person reads it.
func (a *Account) String() string { return a.Name }

// createCommands is what makes the account and its group on goos, in order: busybox's
// pair where shadow's useradd is not installed, and a group made first only when there
// is none of that name already. id is the one macOS gives both, which has no tool that
// picks one.
func createCommands(goos, name string, useradd, groupExists bool, id int) [][]string {
	switch goos {
	case "linux":
		if !useradd {
			cmds := [][]string{{"addgroup", "-S", name}}
			if groupExists {
				cmds = nil
			}

			return append(cmds, []string{"adduser", "-S", "-D", "-H", "-h", "/nonexistent",
				"-s", "/sbin/nologin", "-G", name, "-g", Comment, name})
		}

		cmds := [][]string{{"groupadd", "--system", name}}
		if groupExists {
			cmds = nil
		}

		return append(cmds, []string{"useradd", "--system", "--gid", name, "--no-create-home",
			"--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "--comment", Comment, name})
	case "freebsd":
		cmds := [][]string{{"pw", "groupadd", name}}
		if groupExists {
			cmds = nil
		}

		return append(cmds, []string{"pw", "useradd", name, "-g", name, "-d", "/nonexistent",
			"-s", "/usr/sbin/nologin", "-c", Comment})
	case "openbsd":
		cmds := [][]string{{"groupadd", name}}
		if groupExists {
			cmds = nil
		}

		return append(cmds, []string{"useradd", "-g", name, "-d", "/var/empty", "-s", "/sbin/nologin",
			"-L", "daemon", "-c", Comment, name})
	case "darwin":
		g, u, n := "/Groups/"+name, "/Users/"+name, strconv.Itoa(id)

		return [][]string{
			{"dscl", ".", "-create", g},
			{"dscl", ".", "-create", g, "PrimaryGroupID", n},
			{"dscl", ".", "-create", g, "RealName", Comment},
			{"dscl", ".", "-create", g, "Password", "*"},
			{"dscl", ".", "-create", u},
			{"dscl", ".", "-create", u, "UniqueID", n},
			{"dscl", ".", "-create", u, "PrimaryGroupID", n},
			{"dscl", ".", "-create", u, "UserShell", "/usr/bin/false"},
			{"dscl", ".", "-create", u, "NFSHomeDirectory", "/var/empty"},
			{"dscl", ".", "-create", u, "RealName", Comment},
			{"dscl", ".", "-create", u, "Password", "*"},
			{"dscl", ".", "-create", u, "IsHidden", "1"},
		}
	}

	return nil
}

// removeCommands undoes createCommands. A group left behind once the account has gone --
// userdel removes a same-named one only where the host is set to -- is the caller's to
// remove with the last of them, and only while it still exists.
func removeCommands(goos, name string, useradd bool) [][]string {
	switch goos {
	case "linux":
		if !useradd {
			return [][]string{{"deluser", name}, {"delgroup", name}}
		}

		return [][]string{{"userdel", name}, {"groupdel", name}}
	case "freebsd":
		// pw removes the account's group with it when no other account is in it.
		return [][]string{{"pw", "userdel", name}, {"pw", "groupdel", name}}
	case "openbsd":
		return [][]string{{"userdel", name}, {"groupdel", name}}
	case "darwin":
		return [][]string{{"dscl", ".", "-delete", "/Users/" + name}, {"dscl", ".", "-delete", "/Groups/" + name}}
	}

	return nil
}

// freeID picks the id macOS gives the account and its group: the first in 200-400, where
// Apple keeps its own daemons' accounts, that no user and no group has.
func freeID(taken map[int]bool) (int, error) {
	for id := 200; id <= 400; id++ {
		if !taken[id] {
			return id, nil
		}
	}

	return 0, errors.New("no id between 200 and 400 is free for a system account")
}

// shell renders argv as somebody would type it, for an error that says what to run.
func shell(argv []string) string {
	words := make([]string, len(argv))

	for i, w := range argv {
		if w == "" || strings.ContainsAny(w, " \t\"'*$\\") {
			w = "'" + strings.ReplaceAll(w, "'", `'\''`) + "'"
		}

		words[i] = w
	}

	return strings.Join(words, " ")
}

// howToCreate is the refusal for an account conflux could not make, with the commands
// that would.
func howToCreate(name string, cmds [][]string, err error) error {
	lines := make([]string, len(cmds))
	for i, c := range cmds {
		lines[i] = "  " + shell(c)
	}

	return fmt.Errorf("could not create the account %s that anchord runs as: %w\n"+
		"  create it, and the next start uses it:\n%s", name, err, strings.Join(lines, "\n"))
}
