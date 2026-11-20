//go:build !windows

package group

import (
	"errors"
	"os"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestUsersFrom: who a group lets in, read from what getent and dscl answer -- its listed
// members, and every account whose primary group it is -- so that one that lets anybody in is
// never adopted as the account's own, nor a directory it may write taken for one nobody
// else may.
func TestUsersFrom(t *testing.T) {
	for name, tc := range map[string]struct {
		goos, group, users, gid string
		want                    []string
	}{
		"getent, a group conflux left": {
			goos: "linux", group: "conflux:x:997:\n", gid: "997",
			users: "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n",
		},
		"getent, listed members": {
			goos: "linux", group: "conflux:x:997:alice,bob\n", gid: "997",
			users: "root:x:0:0:root:/root:/bin/bash\n",
			want:  []string{"alice", "bob"},
		},
		"getent, a primary group": {
			goos: "freebsd", group: "conflux:*:997:\n", gid: "997",
			users: "carol:*:1001:997:Carol:/home/carol:/bin/sh\nalice:*:1000:1000::/home/alice:/bin/sh\n",
			want:  []string{"carol"},
		},
		"getent, both, once each": {
			goos: "openbsd", group: "conflux:*:997:carol,alice\n", gid: "997",
			users: "carol:*:1001:997:Carol:/home/carol:/bin/ksh\n",
			want:  []string{"alice", "carol"},
		},
		"dscl, a group conflux left": {
			goos: "darwin", gid: "450",
			group: "AppleMetaNodeLocation: /Local/Default\nPrimaryGroupID: 450\nRecordName: _conflux\n",
			users: "_spotlight       89\nalice            20\n",
		},
		"dscl, members and a primary group": {
			goos: "darwin", gid: "450",
			group: "GroupMembership: alice bob\nPrimaryGroupID: 450\nRecordName: _conflux\n",
			users: "_spotlight       89\ncarol            450\n",
			want:  []string{"alice", "bob", "carol"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := usersFrom(tc.goos, tc.group, tc.users, tc.gid); !slices.Equal(got, tc.want) {
				t.Errorf("usersFrom = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestALookupReadsEachDatabaseOnce: a Lookup answers as Users does, and asks the system for a group's
// record once, and for the account database once, however many times and for however many groups it
// is asked; a record that failed to be read is asked for again, and a new Lookup reads everything
// again.
func TestALookupReadsEachDatabaseOnce(t *testing.T) {
	if files() {
		t.Skip("no getent or dscl here: the databases are read from their files")
	}

	var names []string

	for _, gid := range []string{"0", strconv.Itoa(os.Getgid())} {
		g, err := user.LookupGroupId(gid)
		if err != nil {
			t.Fatal(err)
		}

		names = append(names, g.Name)
	}

	names = slices.Compact(names) // one, as root

	was := output
	t.Cleanup(func() { output = was })

	asked := map[string]int{}

	output = func(argv ...string) (string, error) {
		command := strings.Join(argv, " ")
		asked[command]++

		if strings.HasSuffix(command, "nobody-yet") {
			if asked[command] == 1 {
				return "", errors.New("exit status 2")
			}

			return "nobody-yet:x:4242:\n", nil
		}

		return was(argv...)
	}

	lookups := []*Lookup{{}, {}}

	for _, l := range lookups {
		for range 3 {
			for _, name := range names {
				want, err := Users(name, "0")
				if err != nil {
					t.Fatal(err)
				}

				if got, err := l.Users(name, "0"); err != nil || !slices.Equal(got, want) {
					t.Errorf("Lookup.Users(%s) = %q, %v; Users = %q", name, got, err, want)
				}
			}
		}
	}

	// Users asks for a record, and for the database, at every call; each Lookup once in all.
	calls := 3 * len(lookups)

	for command, n := range asked {
		want := calls + len(lookups) // a group's record
		if strings.Contains(command, "passwd") || strings.Contains(command, "/Users") {
			want = calls*len(names) + len(lookups)
		}

		if n != want {
			t.Errorf("%s was run %d times, want %d", command, n, want)
		}
	}

	l := &Lookup{}

	if _, err := l.Users("nobody-yet", "4242"); err == nil {
		t.Fatal("a Lookup of a group whose record could not be read answered")
	}

	if _, err := l.Users("nobody-yet", "4242"); err != nil {
		t.Errorf("a Lookup did not ask again for a record it failed to read: %v", err)
	}
}
