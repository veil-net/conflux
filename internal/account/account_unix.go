//go:build !windows

package account

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Lookup is this installation's account, or nil when there is none yet. An account or a
// primary group of that name that conflux did not make is ErrConflict.
func Lookup() (*Account, error) { return lookup(Name()) }

// LookupNamed is Lookup for the account of that name: Name's or EphemeralName's.
func LookupNamed(name string) (*Account, error) { return lookup(name) }

func lookup(name string) (*Account, error) {
	u, err := user.Lookup(name)
	if err != nil {
		var unknown user.UnknownUserError
		if errors.As(err, &unknown) {
			return nil, nil
		}

		return nil, err
	}

	if u.Name != Comment {
		return nil, fmt.Errorf("%w: %s (uid %s) does not carry the comment %q", ErrConflict, name, u.Uid, Comment)
	}

	uid, errU := strconv.Atoi(u.Uid)
	gid, errG := strconv.Atoi(u.Gid)

	if errU != nil || errG != nil || uid == 0 || gid == 0 {
		return nil, fmt.Errorf("%w: %s is uid %s, gid %s", ErrConflict, name, u.Uid, u.Gid)
	}

	// Its own group, so the one thing that group is let into -- passing through the state
	// and run directories to anchord's -- is let to nobody else by the group's name.
	if g, err := user.LookupGroupId(u.Gid); err != nil || g.Name != name {
		return nil, fmt.Errorf("%w: the primary group of %s is gid %s and not a group of its own", ErrConflict, name, u.Gid)
	}

	return &Account{Name: name, UID: uid, GID: gid}, nil
}

// Ensure is this installation's account, made first if there is none. Only root can make
// one, and only root calls this.
//
// Looked up again after a creation that failed, since a second conflux making the same
// account at the same moment fails one of the two over an account that now exists.
func Ensure() (*Account, error) { return EnsureNamed(Name()) }

// EnsureNamed is Ensure for the account of that name: Name's or EphemeralName's.
func EnsureNamed(name string) (*Account, error) {
	if a, err := lookup(name); a != nil || err != nil {
		return a, err
	}

	g, err := user.LookupGroup(name)
	groupExists := err == nil

	// A group of the name is adopted as the account's own only when it lets nobody in: one
	// conflux left when making the account failed half-way. One that lets anybody in is
	// somebody else's, and adopting it would give each of them what the account's group is
	// given -- passage to anchord, and on macOS the BPF devices -- and uninstall would then
	// delete a group they rely on.
	if groupExists {
		users, err := groupUsers(name, g.Gid)
		if err != nil {
			return nil, fmt.Errorf("read who the existing group %s lets in: %w", name, err)
		}

		if len(users) > 0 {
			return nil, fmt.Errorf("%w: the group %s already exists and lets in %s, so conflux will not make it its "+
				"account's; remove the group, or take them out of it, if it is conflux's", ErrConflict, name,
				strings.Join(users, ", "))
		}
	}

	cmds, err := planCreate(name, groupExists)
	if err != nil {
		return nil, howToCreate(name, cmds, err)
	}

	for _, c := range cmds {
		if err := run(c); err != nil {
			if a, _ := lookup(name); a != nil {
				return a, nil
			}

			return nil, howToCreate(name, cmds, err)
		}
	}

	// macOS's directory service answers for an account a moment after dscl has made it.
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(200 * time.Millisecond) {
		a, err := lookup(name)
		if a != nil || err != nil {
			return a, err
		}

		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%s was created and cannot be found", name)
		}
	}
}

// groupUsers are the accounts the group of that name lets in: the members it lists, and
// every account it is the primary group of.
func groupUsers(name, gid string) ([]string, error) {
	var groupArgv, usersArgv []string

	// A bare busybox has no getent, and only the files to ask.
	if _, err := exec.LookPath("getent"); err != nil && runtime.GOOS != "darwin" {
		return groupUsersFromFiles(name, gid)
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
		return nil, fmt.Errorf("%s: %w", shell(groupArgv), err)
	}

	users, err := exec.Command(usersArgv[0], usersArgv[1:]...).Output() //nolint:gosec // our own argv
	if err != nil {
		return nil, fmt.Errorf("%s: %w", shell(usersArgv), err)
	}

	return groupUsersFrom(runtime.GOOS, string(group), string(users), gid), nil
}

// groupUsersFromFiles is groupUsers read from /etc/group and /etc/passwd.
func groupUsersFromFiles(name, gid string) ([]string, error) {
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

	return groupUsersFrom(runtime.GOOS, group, string(users), gid), nil
}

// groupUsersFrom reads groupUsers' two answers: getent's group line and passwd database, or
// dscl's group record and its list of each account's primary group.
func groupUsersFrom(goos, group, users, gid string) []string {
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

// planCreate is createCommands for this host.
func planCreate(name string, groupExists bool) ([][]string, error) {
	switch runtime.GOOS {
	case "linux":
		if _, err := exec.LookPath("useradd"); err == nil {
			return createCommands("linux", name, true, groupExists, 0), nil
		}

		if _, err := exec.LookPath("adduser"); err == nil {
			return createCommands("linux", name, false, groupExists, 0), nil
		}

		return createCommands("linux", name, true, groupExists, 0),
			errors.New("this host has neither useradd nor busybox's adduser")
	case "darwin":
		taken, err := darwinIDs()
		if err != nil {
			return createCommands("darwin", name, false, groupExists, 0), err
		}

		id, err := freeID(taken)

		return createCommands("darwin", name, false, groupExists, id), err
	default:
		return createCommands(runtime.GOOS, name, false, groupExists, 0), nil
	}
}

// darwinIDs are the user and group ids in use, which dscl lists and nothing picks among.
func darwinIDs() (map[int]bool, error) {
	taken := map[int]bool{}

	for _, kind := range [][]string{{"/Users", "UniqueID"}, {"/Groups", "PrimaryGroupID"}} {
		out, err := exec.Command("dscl", ".", "-list", kind[0], kind[1]).Output()
		if err != nil {
			return nil, fmt.Errorf("dscl . -list %s %s: %w", kind[0], kind[1], err)
		}

		for line := range strings.Lines(string(out)) {
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}

			if id, err := strconv.Atoi(fields[len(fields)-1]); err == nil {
				taken[id] = true
			}
		}
	}

	return taken, nil
}

// Remove deletes this installation's account and its group, once nothing runs as it, when
// conflux made it. One conflux did not make is left alone, and so is a group another
// account still uses.
func Remove() error { return RemoveNamed(Name()) }

// RemoveNamed is Remove for the account of that name: Name's or EphemeralName's.
func RemoveNamed(name string) error {
	a, err := lookup(name)

	switch {
	case errors.Is(err, ErrConflict):
		return nil
	case err != nil:
		return err
	case a == nil:
		return nil
	}

	if err := Kill(a.UID); err != nil {
		return err
	}

	_, useraddErr := exec.LookPath("userdel")

	var errs []error

	for i, c := range removeCommands(runtime.GOOS, name, useraddErr == nil) {
		// The group, which userdel and pw take with the account where the host is set to.
		if i > 0 {
			if _, err := user.LookupGroup(name); err != nil {
				continue
			}
		}

		if err := run(c); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func run(argv []string) error {
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput() //nolint:gosec // our own argv
	if err != nil {
		return fmt.Errorf("%s: %w: %s", shell(argv), err, strings.TrimSpace(string(out)))
	}

	return nil
}
